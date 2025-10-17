/*
 * Secure Encrypt Tool
 * Author: CYBER JAY
 */

#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>

void display_banner() {
    printf("\n");
    printf("â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“\n");
    printf("â–“                    CYBER JAY                    â–“\n");
    printf("â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“â–“\n");
    printf("\n");
    printf("                    Secure File Encryption Tool\n");
    printf("                    ===========================\n");
    printf("\n");
}

void get_password(char *password, size_t max_len) {
    struct termios old, new;

    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    fgets(password, max_len, stdin);
    password[strcspn(password, "\n")] = 0;

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");
}

void show_help() {
    printf("\nHelp - Secure File Encryption Tool\n");
    printf("==================================\n");
    printf("This tool allows you to encrypt and decrypt files using AES-256 encryption.\n");
    printf("Features:\n");
    printf("- Strong AES-256-CBC encryption with PBKDF2 key derivation\n");
    printf("- HMAC-SHA256 integrity verification\n");
    printf("- Secure password input (hidden)\n");
    printf("- Memory wiping for security\n");
    printf("\nUsage:\n");
    printf("1. Encrypt: Choose option 1, enter input file and output file\n");
    printf("2. Decrypt: Choose option 2, enter input file and output file\n");
    printf("3. File Info: Choose option 3 to check if a file is encrypted\n");
    printf("4. Help: Display this help information\n");
    printf("5. Exit: Quit the program\n");
    printf("\nSecurity Notes:\n");
    printf("- Use strong, unique passwords\n");
    printf("- Encrypted files have .enc extension by default\n");
    printf("- Always verify file integrity after operations\n");
    printf("\n");
}

int is_encrypted_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) return 0;

    crypto_header_t header;
    size_t read = fread(&header, sizeof(crypto_header_t), 1, file);
    fclose(file);

    // Check if header looks valid (basic check)
    if (read != 1) return 0;

    // Check salt and IV are not all zeros (basic validation)
    int has_data = 0;
    for (int i = 0; i < SALT_SIZE; i++) {
        if (header.salt[i] != 0) has_data = 1;
    }
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        if (header.iv[i] != 0) has_data = 1;
    }

    return has_data;
}

void show_file_info(const char *filename) {
    if (access(filename, F_OK) != 0) {
        printf("File '%s' does not exist.\n", filename);
        return;
    }

    int is_encrypted = is_encrypted_file(filename);

    printf("\nFile Information:\n");
    printf("================\n");
    printf("Filename: %s\n", filename);
    printf("Status: %s\n", is_encrypted ? "Encrypted" : "Not encrypted");

    // Get file size
    FILE *file = fopen(filename, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fclose(file);
        printf("Size: %ld bytes\n", size);
    }

    if (is_encrypted) {
        printf("Note: This appears to be an encrypted file created by this tool.\n");
    } else {
        printf("Note: This appears to be a regular file.\n");
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    display_banner();

    int choice;
    char input_file[256];
    char output_file[256];
    char password[256];

    while (1) {
        printf("Main Menu:\n");
        printf("==========\n");
        printf("1. Encrypt a file\n");
        printf("2. Decrypt a file\n");
        printf("3. Check file information\n");
        printf("4. Help\n");
        printf("5. Exit\n");
        printf("Enter your choice (1-5): ");

        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Please enter a number.\n");
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }

        if (choice == 5) {
            printf("\nThank you for using Secure Encrypt Tool!\n");
            printf("Created by CYBER JAY\n");
            break;
        }

        // Clear input buffer
        while (getchar() != '\n');

        switch (choice) {
            case 1: // Encrypt
                printf("Enter input file path: ");
                if (fgets(input_file, sizeof(input_file), stdin) == NULL) {
                    printf("Error reading input.\n");
                    continue;
                }
                input_file[strcspn(input_file, "\n")] = 0;

                printf("Enter output file path (or press Enter for auto .enc extension): ");
                if (fgets(output_file, sizeof(output_file), stdin) == NULL) {
                    printf("Error reading input.\n");
                    continue;
                }
                output_file[strcspn(output_file, "\n")] = 0;

                // Auto-add .enc extension if output file is empty
                if (strlen(output_file) == 0) {
                    snprintf(output_file, sizeof(output_file), "%s.enc", input_file);
                }

                printf("Enter password: ");
                get_password(password, sizeof(password));

                printf("Encrypting file...\n");
                if (encrypt_file(input_file, output_file, password) == 0) {
                    printf("âœ“ Encryption completed successfully!\n");
                    printf("Output file: %s\n", output_file);
                } else {
                    printf("âœ— Encryption failed. Check file paths and permissions.\n");
                }
                break;

            case 2: // Decrypt
                printf("Enter encrypted file path: ");
                if (fgets(input_file, sizeof(input_file), stdin) == NULL) {
                    printf("Error reading input.\n");
                    continue;
                }
                input_file[strcspn(input_file, "\n")] = 0;

                printf("Enter output file path: ");
                if (fgets(output_file, sizeof(output_file), stdin) == NULL) {
                    printf("Error reading input.\n");
                    continue;
                }
                output_file[strcspn(output_file, "\n")] = 0;

                printf("Enter password: ");
                get_password(password, sizeof(password));

                printf("Decrypting file...\n");
                if (decrypt_file(input_file, output_file, password) == 0) {
                    printf("âœ“ Decryption completed successfully!\n");
                    printf("Output file: %s\n", output_file);
                } else {
                    printf("âœ— Decryption failed. Check password and file integrity.\n");
                }
                break;

            case 3: // File info
                printf("Enter file path to check: ");
                if (fgets(input_file, sizeof(input_file), stdin) == NULL) {
                    printf("Error reading input.\n");
                    continue;
                }
                input_file[strcspn(input_file, "\n")] = 0;
                show_file_info(input_file);
                break;

            case 4: // Help
                show_help();
                break;

            default:
                printf("Invalid choice. Please select 1-5.\n");
                break;
        }

        secure_wipe(password, sizeof(password));

        printf("\nPress Enter to continue...");
        while (getchar() != '\n');
        printf("\n");
    }

    return 0;
}
