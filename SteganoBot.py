import os
import logging
import random
import json
import base64
from io import BytesIO
from PIL import Image
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ConversationHandler,
    ContextTypes,
)

# Mengaktifkan logging untuk melihat error
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
# Ganti level ke logging.DEBUG untuk melihat log yang lebih detail jika diperlukan
# logging.basicConfig(
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG
# )
logger = logging.getLogger(__name__)

# --- Konstanta dan Helper untuk Penyimpanan Kunci ---
KEY_STORAGE_FILE = "user_keys.json"

def load_keys() -> dict:
    """Memuat kunci dari file JSON."""
    try:
        with open(KEY_STORAGE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_keys(keys: dict) -> None:
    """Menyimpan kunci ke file JSON."""
    with open(KEY_STORAGE_FILE, 'w') as f:
        json.dump(keys, f, indent=4)

# ==============================================================================
# BAGIAN 1: FUNGSI-FUNGSI INTI (KRIPTOGRAFI & STEGANOGRAFI)
# ==============================================================================

def encrypt_payload(message: str, public_key_pem: bytes) -> bytes:
    message_bytes = message.encode('utf-8')
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message_bytes)
    recipient_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    return encrypted_session_key + cipher_aes.nonce + tag + ciphertext

def decrypt_payload(payload: bytes, private_key_pem: bytes) -> str:
    try:
        logger.debug(f"Payload untuk dekripsi diterima (ukuran: {len(payload)} bytes)")
        encrypted_session_key = payload[:256]
        nonce = payload[256:256+16]
        tag = payload[256+16:256+32]
        ciphertext = payload[256+32:]
        
        private_key = RSA.import_key(private_key_pem)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)
        
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted_message_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return decrypted_message_bytes.decode('utf-8')
    except (ValueError, IndexError) as e:
        logger.error(f"Gagal mendekripsi payload: {e}")
        return None

def to_binary(data: bytes) -> str:
    return ''.join(f"{byte:08b}" for byte in data)

def from_binary(bit_string: str) -> bytes:
    byte_array = bytearray()
    for i in range(0, len(bit_string), 8):
        byte_chunk = bit_string[i:i+8]
        if len(byte_chunk) == 8:
            byte = int(byte_chunk, 2)
            byte_array.append(byte)
    return bytes(byte_array)

def embed_data(image_stream: BytesIO, data: bytes, stego_password: str) -> BytesIO:
    image = Image.open(image_stream).convert('RGB')
    data_to_embed = len(data).to_bytes(8, 'big') + data
    binary_data = to_binary(data_to_embed)
    width, height = image.size
    total_pixels = width * height
    if len(binary_data) > total_pixels * 3:
        raise ValueError("Ukuran data melebihi kapasitas gambar.")
    pixels = list(image.getdata())
    random.seed(stego_password)
    shuffled_indices = list(range(total_pixels))
    random.shuffle(shuffled_indices)
    data_idx = 0
    for pixel_idx in shuffled_indices:
        if data_idx >= len(binary_data): break
        r, g, b = pixels[pixel_idx]
        new_r, new_g, new_b = r, g, b
        if data_idx < len(binary_data): new_r = (r & 0xFE) | int(binary_data[data_idx]); data_idx += 1
        if data_idx < len(binary_data): new_g = (g & 0xFE) | int(binary_data[data_idx]); data_idx += 1
        if data_idx < len(binary_data): new_b = (b & 0xFE) | int(binary_data[data_idx]); data_idx += 1
        pixels[pixel_idx] = (new_r, new_g, new_b)
    new_image = Image.new('RGB', (width, height))
    new_image.putdata(pixels)
    output_stream = BytesIO()
    new_image.save(output_stream, format='PNG')
    output_stream.seek(0)
    return output_stream

def extract_data(stego_image_stream: BytesIO, stego_password: str) -> bytes:
    image = Image.open(stego_image_stream).convert('RGB')
    pixels = list(image.getdata())
    total_pixels = len(pixels)
    random.seed(stego_password)
    shuffled_indices = list(range(total_pixels))
    random.shuffle(shuffled_indices)
    binary_data = ""
    for pixel_idx in shuffled_indices:
        r, g, b = pixels[pixel_idx]
        binary_data += str(r & 1) + str(g & 1) + str(b & 1)
    if len(binary_data) < 64:
        raise ValueError("Gagal mengekstrak header: Gambar terlalu kecil.")
    header_bits = binary_data[:64]
    payload_len_in_bytes = int.from_bytes(from_binary(header_bits), 'big')
    logger.info(f"Header Ditemukan. Panjang payload yang diharapkan: {payload_len_in_bytes} bytes.")
    total_bits_to_extract = 64 + (payload_len_in_bytes * 8)
    if len(binary_data) < total_bits_to_extract:
        raise ValueError(f"Gagal mengekstrak payload: Data gambar tidak lengkap atau korup.")
    payload_bits = binary_data[64:total_bits_to_extract]
    extracted_payload = from_binary(payload_bits)
    logger.info(f"Ekstraksi berhasil. Ukuran payload: {len(extracted_payload)} bytes.")
    return extracted_payload

# ==============================================================================
# BAGIAN 2: PENGATURAN BOT TELEGRAM (DIPERBARUI DENGAN MANAJEMEN KUNCI)
# ==============================================================================

# Definisikan state baru
(SELECTING_ACTION, 
 SELECT_KEY_METHOD, GET_PUBLIC_KEY_UPLOAD, GET_MESSAGE, GET_COVER_IMAGE, GET_EMBED_PASSWORD,
 GET_PRIVATE_KEY, GET_STEGO_IMAGE, GET_EXTRACT_PASSWORD,
 ASK_FOR_KEY_LABEL, GET_KEY_FILE_TO_SAVE,
 CHOOSE_KEY_TO_DELETE
) = range(12)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    reply_keyboard = [['/embed', '/extract'], ['/savekey', '/listkeys', '/deletekey'], ['/generatekeys']]
    await update.message.reply_text(
        'Selamat datang di Bot Steganografi!\n\n'
        'Pilih perintah dari menu di bawah.',
        reply_markup=ReplyKeyboardMarkup(reply_keyboard, resize_keyboard=True),
    )
    return ConversationHandler.END

async def generate_keys(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Membuat pasangan kunci RSA 2048-bit...")
    key = RSA.generate(2048)
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()
    await context.bot.send_document(chat_id=update.effective_chat.id, document=BytesIO(private_key_pem), filename="private.pem", caption="KUNCI PRIVAT Anda. JANGAN bagikan!")
    await context.bot.send_document(chat_id=update.effective_chat.id, document=BytesIO(public_key_pem), filename="public.pem", caption="KUNCI PUBLIK Anda. Bagikan ini ke pengirim.")

# --- Alur Manajemen Kunci ---

async def save_key_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Masukkan nama/label untuk kunci publik ini (contoh: Budi).", reply_markup=ReplyKeyboardRemove())
    return ASK_FOR_KEY_LABEL

async def ask_for_key_label(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['key_label'] = update.message.text
    await update.message.reply_text(f"Label '{context.user_data['key_label']}' diterima. Sekarang, kirim file `public.pem` yang ingin Anda simpan.")
    return GET_KEY_FILE_TO_SAVE

async def get_key_file_to_save(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    doc_file = await update.message.document.get_file()
    key_stream = BytesIO()
    await doc_file.download_to_memory(key_stream)
    key_stream.seek(0)
    key_content = key_stream.read()
    
    try:
        RSA.import_key(key_content)
        logger.info("Kunci publik yang akan disimpan berhasil divalidasi.")
    except Exception as e:
        await update.message.reply_text(f"Error: File kunci publik tidak valid. ({e})")
        context.user_data.clear()
        return ConversationHandler.END

    keys = load_keys()
    keys[context.user_data['key_label']] = base64.b64encode(key_content).decode('utf-8')
    save_keys(keys)
    
    await update.message.reply_text(f"Kunci publik untuk '{context.user_data['key_label']}' berhasil disimpan!")
    context.user_data.clear()
    return ConversationHandler.END

async def list_keys(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keys = load_keys()
    if not keys:
        await update.message.reply_text("Belum ada kunci publik yang tersimpan.")
        return
    message = "Daftar kunci publik yang tersimpan:\n\n"
    for label in keys.keys():
        message += f"\\- `{label}`\n"
    await update.message.reply_text(message, parse_mode='MarkdownV2')

async def delete_key_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    keys = load_keys()
    if not keys:
        await update.message.reply_text("Tidak ada kunci untuk dihapus.", reply_markup=ReplyKeyboardRemove())
        return ConversationHandler.END
    keyboard = [[label] for label in keys.keys()]
    await update.message.reply_text("Pilih kunci yang ingin dihapus:", reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True))
    return CHOOSE_KEY_TO_DELETE

async def choose_key_to_delete(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    label_to_delete = update.message.text
    keys = load_keys()
    if label_to_delete in keys:
        del keys[label_to_delete]
        save_keys(keys)
        await update.message.reply_text(f"Kunci '{label_to_delete}' berhasil dihapus.", reply_markup=ReplyKeyboardRemove())
    else:
        await update.message.reply_text(f"Kunci '{label_to_delete}' tidak ditemukan.", reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END

# --- Alur Embed yang Diperbarui ---

async def embed_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    keys = load_keys()
    if not keys:
        await update.message.reply_text("Belum ada kunci tersimpan. Silakan unggah file kunci publik (`public.pem`) milik penerima.", reply_markup=ReplyKeyboardRemove())
        return GET_PUBLIC_KEY_UPLOAD
    keyboard = [[label for label in keys.keys()], ["Unggah Kunci Baru"]]
    await update.message.reply_text(
        "Pilih kunci publik penerima dari daftar di bawah, atau unggah yang baru.",
        reply_markup=ReplyKeyboardMarkup(keyboard, one_time_keyboard=True, resize_keyboard=True)
    )
    return SELECT_KEY_METHOD

async def select_key_method(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    choice = update.message.text
    if choice == "Unggah Kunci Baru":
        await update.message.reply_text("Silakan unggah file kunci publik (`public.pem`).", reply_markup=ReplyKeyboardRemove())
        return GET_PUBLIC_KEY_UPLOAD
    keys = load_keys()
    if choice in keys:
        key_content_b64 = keys[choice]
        context.user_data['public_key'] = base64.b64decode(key_content_b64)
        logger.info(f"Kunci publik '{choice}' dipilih dari penyimpanan.")
        await update.message.reply_text(f"Kunci untuk '{choice}' dipilih. Sekarang, kirim pesan rahasia Anda.", reply_markup=ReplyKeyboardRemove())
        return GET_MESSAGE
    else:
        await update.message.reply_text("Pilihan tidak valid. Silakan coba lagi.", reply_markup=ReplyKeyboardRemove())
        return ConversationHandler.END

async def get_public_key_upload(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    doc_file = await update.message.document.get_file()
    key_stream = BytesIO()
    await doc_file.download_to_memory(key_stream)
    key_stream.seek(0)
    key_bytes = key_stream.read()
    try:
        RSA.import_key(key_bytes)
        logger.info("Kunci publik yang diunggah berhasil divalidasi.")
        context.user_data['public_key'] = key_bytes
    except Exception as e:
        await update.message.reply_text(f"Error: File kunci publik tidak valid. ({e})")
        return ConversationHandler.END
    await update.message.reply_text('Kunci publik diterima. Sekarang, kirim pesan rahasia yang ingin Anda sembunyikan.')
    return GET_MESSAGE

async def get_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['message'] = update.message.text
    await update.message.reply_text('Pesan diterima. Kirim gambar sebagai "File/Dokumen".')
    return GET_COVER_IMAGE

async def get_cover_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    doc_file = await update.message.document.get_file()
    image_stream = BytesIO()
    await doc_file.download_to_memory(image_stream)
    context.user_data['image_stream'] = image_stream
    await update.message.reply_text('Gambar diterima. Masukkan password steganografi.')
    return GET_EMBED_PASSWORD

async def get_embed_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    password = update.message.text
    await update.message.reply_text('Memproses, mohon tunggu...')
    try:
        encrypted_payload = encrypt_payload(context.user_data['message'], context.user_data['public_key'])
        stego_image_stream = embed_data(context.user_data['image_stream'], encrypted_payload, password)
        await context.bot.send_document(chat_id=update.effective_chat.id, document=stego_image_stream, filename="stego_image.png", caption='Proses selesai!')
    except Exception as e:
        await update.message.reply_text(f'Terjadi kesalahan: {e}')
    context.user_data.clear()
    return ConversationHandler.END

# --- Alur Extract (Hanya nama state yang disesuaikan) ---
async def extract_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text('Kirim file kunci privat (`private.pem`) Anda.', reply_markup=ReplyKeyboardRemove())
    return GET_PRIVATE_KEY

async def get_private_key(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    doc_file = await update.message.document.get_file()
    key_stream = BytesIO()
    await doc_file.download_to_memory(key_stream)
    key_stream.seek(0)
    key_bytes = key_stream.read()
    try:
        RSA.import_key(key_bytes)
        logger.info("Kunci privat berhasil divalidasi saat diunggah.")
        context.user_data['private_key'] = key_bytes
    except Exception as e:
        logger.error(f"Gagal mengimpor kunci privat saat diunggah: {e}")
        await update.message.reply_text(f"Error: Format kunci privat tidak valid atau file korup. Pastikan Anda mengunggah file .pem yang benar.")
        return ConversationHandler.END
    await update.message.reply_text('Kunci privat diterima. Kirim gambar (sebagai File/Dokumen).')
    return GET_STEGO_IMAGE

async def get_stego_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    doc_file = await update.message.document.get_file()
    image_stream = BytesIO()
    await doc_file.download_to_memory(image_stream)
    context.user_data['stego_image_stream'] = image_stream
    await update.message.reply_text('Gambar diterima. Masukkan password.')
    return GET_EXTRACT_PASSWORD

async def get_extract_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    password = update.message.text
    await update.message.reply_text('Mencoba mengekstrak pesan...')
    try:
        extracted_payload = extract_data(context.user_data['stego_image_stream'], password)
        decrypted_message = decrypt_payload(extracted_payload, context.user_data['private_key'])
        if decrypted_message:
            await update.message.reply_text(f'Pesan berhasil diekstrak:\n\n"{decrypted_message}"')
        else:
            await update.message.reply_text('Gagal mendekripsi pesan. Pastikan kunci privat dan password benar.')
    except Exception as e:
        await update.message.reply_text(f'Terjadi kesalahan: {e}')
    context.user_data.clear()
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text('Proses dibatalkan.', reply_markup=ReplyKeyboardRemove())
    context.user_data.clear()
    return ConversationHandler.END

def main() -> None:
    TOKEN = "GANTI_DENGAN_TOKEN_BOT_ANDA"
    if TOKEN == "GANTI_DENGAN_TOKEN_BOT_ANDA":
        print("!!! PENTING: Harap ganti 'GANTI_DENGAN_TOKEN_BOT_ANDA' dengan token API bot Anda di dalam kode.")
        return

    application = Application.builder().token(TOKEN).build()

    # Conversation handler untuk menyimpan kunci
    save_key_conv = ConversationHandler(
        entry_points=[CommandHandler('savekey', save_key_start)],
        states={
            ASK_FOR_KEY_LABEL: [MessageHandler(filters.TEXT & ~filters.COMMAND, ask_for_key_label)],
            GET_KEY_FILE_TO_SAVE: [MessageHandler(filters.Document.FileExtension("pem"), get_key_file_to_save)],
        },
        fallbacks=[CommandHandler('cancel', cancel)]
    )

    # Conversation handler untuk menghapus kunci
    delete_key_conv = ConversationHandler(
        entry_points=[CommandHandler('deletekey', delete_key_start)],
        states={
            CHOOSE_KEY_TO_DELETE: [MessageHandler(filters.TEXT & ~filters.COMMAND, choose_key_to_delete)]
        },
        fallbacks=[CommandHandler('cancel', cancel)]
    )

    # Conversation handler utama untuk embed dan extract
    main_conv = ConversationHandler(
        entry_points=[CommandHandler('embed', embed_start), CommandHandler('extract', extract_start)],
        states={
            # Embed flow
            SELECT_KEY_METHOD: [MessageHandler(filters.TEXT & ~filters.COMMAND, select_key_method)],
            GET_PUBLIC_KEY_UPLOAD: [MessageHandler(filters.Document.FileExtension("pem"), get_public_key_upload)],
            GET_MESSAGE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_message)],
            GET_COVER_IMAGE: [MessageHandler(filters.Document.IMAGE, get_cover_image)],
            GET_EMBED_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_embed_password)],
            # Extract flow
            GET_PRIVATE_KEY: [MessageHandler(filters.Document.FileExtension("pem"), get_private_key)],
            GET_STEGO_IMAGE: [MessageHandler(filters.Document.IMAGE, get_stego_image)],
            GET_EXTRACT_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_extract_password)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("generatekeys", generate_keys))
    application.add_handler(CommandHandler("listkeys", list_keys))
    application.add_handler(save_key_conv)
    application.add_handler(delete_key_conv)
    application.add_handler(main_conv)
    
    logger.info("Bot telah dimulai. Tekan Ctrl+C untuk berhenti.")
    application.run_polling()

if __name__ == '__main__':
    main()
