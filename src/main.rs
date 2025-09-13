use std::fs;

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit,
};
use base64::prelude::*;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};


// / Save bytes to file encoded as Base64.
// /
// / The data is encoded using the standard Base64 encoding engine and written to
// / disk.
// /
// / # Arguments
// /
// / * `file_name` - the path of the file in which the data is to be saved
// / * `data` - the data of to be saved to file
// /
// / # Note
// /
// / You may **not** change the signature of this function.
// /
fn save_to_file_as_b64(file_name: &str, data: &[u8]) {
    // TODO
    let encoded_data = BASE64_STANDARD.encode(data);
    fs::write(file_name,encoded_data).unwrap();
    
}

// / Read a Base64-encoded file as bytes.
// /
// / The data is read from disk and decoded using the standard Base64 encoding
// / engine.
// /
// / # Note
// /
// / You may **not** change the signature of this function.
// /
fn read_from_b64_file(file_name: &str) -> Vec<u8> {
    // TODO
    let file_contents = fs::read(file_name).unwrap();
    // println!("{:?}", file_contents);
    return BASE64_STANDARD.decode(file_contents).unwrap();
}

/// Returns a tuple containing a randomly generated secret key and public key.
///
/// The secret key is a StaticSecret that can be used in a Diffie-Hellman key
/// exchange. The public key is the associated PublicKey for the StaticSecret.
/// The output of this function is a tuple of bytes corresponding to these keys.
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn keygen() -> ([u8; 32], [u8; 32]) {
    // TODO
    let private_key = StaticSecret::new(&mut OsRng);
    let public_key = PublicKey::from(&private_key);
    (private_key.to_bytes(), public_key.to_bytes())
}

// / Returns the encryption of plaintext data to be sent from a sender to a receiver.
// /
// / This function performs a Diffie-Hellman key exchange between the sender's
// / secret key and the receiver's public key. Then, the function uses SHA-256 to
// / derive a symmetric encryption key, which is then used in an AES-256-GCM
// / encryption operation. The output vector contains the ciphertext with the
// / AES-256-GCM nonce (12 bytes long) appended to its end.
// /
// / # Arguments
// /
// / * `input` - A vector of bytes (`u8`) that represents the plaintext data to be encrypted.
// / * `sender_sk` - An array of bytes representing the secret key of the sender.
// / * `receiver_pk` - An array of bytes representing the public key of the receiver.
// /
// / # Note
// /
// / You may **not** change the signature of this function.
// /
fn encrypt(input: Vec<u8>, sender_sk: [u8; 32], receiver_pk: [u8; 32]) -> Vec<u8> {
    // TODO
    let sender_secret_key = StaticSecret::from(sender_sk);
    let receiver_public_key = PublicKey::from(receiver_pk);
    
    let shared_secret = sender_secret_key.diffie_hellman(&receiver_public_key);
    let hashed_secret = Sha256::digest(shared_secret.as_bytes());

    let AES_key = Key::<Aes256Gcm>::from_slice(&hashed_secret);
    let  cipher = Aes256Gcm::new(AES_key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let mut ciphertext = cipher.encrypt(&nonce, input.as_ref()).unwrap();

    ciphertext.extend_from_slice(nonce.as_slice());
    ciphertext

}


// /// Returns the decryption of ciphertext data to be received by a receiver from a sender.
// ///
// /// This function performs a Diffie-Hellman key exchange between the receiver's
// /// secret key and the sender's public key. Then, the function uses SHA-256 to
// /// derive a symmetric encryption key, which is then used in an AES-256-GCM
// /// decryption operation. The nonce for this decryption is the last 12 bytes of
// /// the input. The output vector contains the plaintext.
// ///
// /// # Arguments
// ///
// /// * `input` - A vector of bytes that represents the ciphertext data to be encrypted and the associated nonce.
// /// * `receiver_sk` - An array of bytes representing the secret key of the receiver.
// /// * `sender_pk` - An array of bytes representing the public key of the sender.
// ///
// /// # Note
// ///
// /// You may **not** change the signature of this function.
// ///
fn decrypt(input: Vec<u8>, receiver_sk: [u8; 32], sender_pk: [u8; 32]) -> Vec<u8> {
    // TODO
    let receiver_secret_key = StaticSecret::from(receiver_sk);
    let sender_public_key = PublicKey::from(sender_pk);

    let shared_secret = receiver_secret_key.diffie_hellman(&sender_public_key);
    let hashed_secret = Sha256::digest(shared_secret.as_bytes());

    let AES_key = Key::<Aes256Gcm>::from_slice(&hashed_secret);
    let cipher = Aes256Gcm::new(AES_key);

    let nonce_bytes_len = 12;
    let split_at = input.len() - nonce_bytes_len;
    let (ciphertext, nonce_bytes) = input.split_at(split_at);

    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    plaintext
}

/// The main function, which parses arguments and calls the correct cryptographic operations.
///
/// # Note
///
/// **Do not modify this function**.
///
fn main() {
    // Collect command line arguments
    let args: Vec<String> = std::env::args().collect();

    // Command parsing: keygen, encrypt, decrypt
    let cmd = &args[1];
    if cmd == "keygen" {
        // Arguments to the command
        let secret_key = &args[2];
        let public_key = &args[3];

        // Generate a secret and public key for this user
        let (sk_bytes, pk_bytes) = keygen();

        // Save those bytes as Base64 to file
        save_to_file_as_b64(&secret_key, &sk_bytes);
        save_to_file_as_b64(&public_key, &pk_bytes);
    } else if cmd == "encrypt" {
        // Arguments to the command
        let input = &args[2];
        let output = &args[3];
        let sender_sk = &args[4];
        let receiver_pk = &args[5];

        // Read input from file
        // Note that this input is not necessarily Base64-encoded
        let input = fs::read(input).unwrap();

        // Read the base64-encoded secret and public keys from file
        // Need to convert the Vec<u8> from this function into the 32-byte array for each key
        let sender_sk: [u8; 32] = read_from_b64_file(sender_sk).try_into().unwrap();
        let receiver_pk: [u8; 32] = read_from_b64_file(receiver_pk).try_into().unwrap();

        // Call the encryption operation
        let output_bytes = encrypt(input, sender_sk, receiver_pk);

        // Save those bytes as Base64 to file
        save_to_file_as_b64(&output, &output_bytes);
    } else if cmd == "decrypt" {
        // Arguments to the command
        let input = &args[2];
        let output = &args[3];
        let receiver_sk = &args[4];
        let sender_pk = &args[5];

        // Read the Base64-encoded input ciphertext from file
        let input = read_from_b64_file(&input);

        // Read the base64-encoded secret and public keys from file
        // Need to convert the Vec<u8> from this function into the 32-byte array for each key
        let receiver_sk: [u8; 32] = read_from_b64_file(&receiver_sk).try_into().unwrap();
        let sender_pk: [u8; 32] = read_from_b64_file(&sender_pk).try_into().unwrap();

        // Call the decryption operation
        let output_bytes = decrypt(input, receiver_sk, sender_pk);

        // Save those bytes as Base64 to file
        fs::write(output, output_bytes).unwrap();
    } else {
        panic!("command not found!")
    }



}

#[cfg(test)]
mod tests {
    use super::*;
    // TODO: Write tests that validate your encryption and decryption functionality
    // Use the values in README.md to write these tests
    // You may have to split up function to write tests
    // For example, how can you test that both parties reach the same AES key?
    #[test]
    fn test_encryption_generates_ciphertext(){
        // Generating sender keys
        let (sender_secret_key_bytes,sender_public_key_bytes) = keygen();
        //generating receiver keys
        let (receiver_secret_key_bytes,receiver_public_key_bytes) = keygen();

        let plaintext = fs::read("readme.md").expect("Failed to read readme.md file");

        // Encrypt
        let ciphertext = encrypt(
            plaintext.clone(),
            sender_secret_key_bytes,
            receiver_public_key_bytes,
        );

        // Check that ciphertext is not equal to plaintext
        assert_ne!(ciphertext, plaintext, "Ciphertext should be different from plaintext");

        //Ciphertext should be longer than plaintext due to appended nonce
        assert!(ciphertext.len() > plaintext.len(), "Ciphertext should include nonce");
    }
    #[test]
    fn test_decryption_returns_original_text() {
        // Generating sender keys
        let (sender_secret_key_bytes,sender_public_key_bytes) = keygen();
        //generating receiver keys
        let (receiver_secret_key_bytes,receiver_public_key_bytes) = keygen();

        // Read plaintext from file
        let plaintext = fs::read("readme.md").expect("Failed to read readme.md file");

        // Encrypt with sender's secret key and receiver's public key
        let ciphertext = encrypt(
            plaintext.clone(),
            sender_secret_key_bytes,
            receiver_public_key_bytes,
        );

        // Decrypt with receiver's secret key and sender's public key
        let decrypted_text = decrypt(
            ciphertext,
            receiver_secret_key_bytes,
            sender_public_key_bytes,
        );

        // check that decrypted data matches original plaintext
        assert_eq!(
            decrypted_text,
            plaintext,
            "Decrypted text should match the content of readme.md"
        );
}

    #[test]
    fn test_both_parties_share_reach_aes_key() {
        // Generating sender keys
        let sender_secret_key = StaticSecret::new(&mut OsRng);
        let sender_public_key = PublicKey::from(&sender_secret_key);
        //generating receiver keys
        let receiver_secret_key = StaticSecret::new(&mut OsRng);
        let receiver_public_key = PublicKey::from(&receiver_secret_key);

        // Sender generates shared secret
        let sender_shared_secret = sender_secret_key.diffie_hellman(&receiver_public_key);
        let sender_aes_key = Sha256::digest(sender_shared_secret.as_bytes());

        // Receiver generates shared secret
        let receiver_shared_secret = receiver_secret_key.diffie_hellman(&sender_public_key);
        let receiver_aes_key = Sha256::digest(receiver_shared_secret.as_bytes());

        // Check that both AES keys are identical
        assert_eq!(sender_aes_key, receiver_aes_key, "AES keys do not match!");
    }



}
