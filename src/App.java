import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.InputMismatchException;
import java.util.NoSuchElementException;
import java.util.Scanner;

/*
    AES Encrypt-Decrypt Application
    This app will encrypt/decrypt a plaintext/ciphertext read from a text file.
    It will write the encrypted results to a text file ciphertext.txt and
    write the decrypted results to a text file plaintext.txt.
    The random generated key will be stored in a KeyStore.

    Luana Kimley
 */

public class App
{
    public static void main(String[] args)
    {
        App app = new App();
        app.menu();
    }

    public void menu()
    {
        final String MENU_ITEMS = "\n*** AES ENCRYPT/DECRYPT MAIN MENU ***\n"
                + "1. Encrypt\n"
                + "2. Decrypt\n"
                + "3. Exit\n"
                + "Enter Option [1,3]";

        final int ENCRYPT = 1;
        final int DECRYPT = 2;
        final int EXIT = 3;

        Scanner keyboard = new Scanner(System.in);
        int option = 0;
        do
        {
            System.out.println("\n" + MENU_ITEMS);
            try
            {
                String usersInput = keyboard.nextLine();
                option = Integer.parseInt(usersInput);
                switch (option)
                {
                    case ENCRYPT:
                        encryptMenu();
                        break;
                    case DECRYPT:
                        decryptMenu();
                        break;
                    case EXIT:
                        System.out.println("Exit menu option chosen");
                        break;
                    default:
                        System.out.print("Invalid input - please enter number in range");
                        break;
                }

            } catch (InputMismatchException | NumberFormatException e)
            {
                System.out.print("Invalid input - please enter number in range");
            }
        } while (option != EXIT);

        System.out.println("\nProgram ending, goodbye.");

    }

    public void encryptMenu()
    {
        AES aes = new AES();

        Scanner keyboard = new Scanner(System.in);
        System.out.println("Encrypt option chosen");
        System.out.println("Enter plain text file name:");
        String fileName = keyboard.nextLine();
        System.out.println("Enter key size (128/192/256):");
        int keySize = keyboard.nextInt();
        while (keySize != 128 && keySize != 192 && keySize != 256)
        {
            System.out.println("Enter key size (128/192/256):");
            keySize = keyboard.nextInt();
        }

        try
        {
            File file = new File(fileName);
            Scanner input = new Scanner(file);

            StringBuilder plainText = new StringBuilder();
            while (input.hasNextLine())
            {
                plainText.append(input.nextLine());
                plainText.append("\n"); // to preserve line breaks
            }

            String cipherText = aes.encrypt(keySize, plainText.toString());
            aes.storeToKeyStore("keystore.keystore", "D00234604");

            String outFile = "ciphertext.txt";
            PrintWriter out = new PrintWriter(outFile);
            out.println(cipherText);
            out.close();

            Path path = Paths.get(outFile);

            System.out.println("\nText encrypted, encrypted text is stored in " + path.toAbsolutePath());
            System.out.println("Key: " + aes.getKeyString());

            Path keyStorePath = Paths.get("keystore.keystore");
            System.out.println("Key is stored in " + keyStorePath.toAbsolutePath());

        }
        catch (NoSuchElementException | FileNotFoundException e)
        {
            System.out.println("File read fail - file not found/file is empty");
        }
    }

    public void decryptMenu()
    {
        AES aes = new AES();

        Scanner keyboard = new Scanner(System.in);
        System.out.println("Decrypt option chosen");

        System.out.println("Enter cipher text file name:");
        String fileName = keyboard.nextLine();

        try
        {
            File file = new File(fileName);
            Scanner input = new Scanner(file);
            String cipherText = input.nextLine();

            System.out.println("Enter KeyStore file name:");
            String keyStoreFile = keyboard.nextLine();

            System.out.println("Enter KeyStore password:");
            String password = keyboard.nextLine();

            aes.loadFromKeyStore(keyStoreFile, password);
            String plainText = aes.decrypt(cipherText);

            if (!plainText.equalsIgnoreCase("Decryption failed"))
            {

                String outFile = "plaintext.txt";
                PrintWriter out = new PrintWriter(outFile);
                out.println(plainText);
                out.close();

                Path path = Paths.get(outFile);
                System.out.println("\nText decrypted, decrypted text is stored in " + path.toAbsolutePath());
            }
            else
            {
                System.out.println("Decryption failed");
            }



        }
        catch (NoSuchElementException | FileNotFoundException e)
        {
            System.out.println("File read fail - file not found/file is empty");
        }
    }
}
