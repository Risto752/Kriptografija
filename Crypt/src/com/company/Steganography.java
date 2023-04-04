package com.company;


import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;



public class Steganography {

    public static void encode(File carrier, String payload, String sendTo, boolean isEnd) {
        int pos = locatePixelArray(carrier);
        int readByte = 0;
        File stegoFile = new File(
                carrier.getAbsolutePath().substring(0, carrier.getAbsolutePath().length() - 4) + "_stego.bmp");
        try {
            Files.copy(carrier.toPath(), stegoFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        try (RandomAccessFile stream = new RandomAccessFile(stegoFile, "rw")) {
            stream.seek(pos);
            for (int i = 0; i < 32; i++) {
                readByte = stream.read();
                stream.seek(pos);
                stream.write(readByte & 0b11111110);
                pos++;
            }

            payload += (char) 0;
            int payloadByte;
            int payloadBit;
            int newByte;
            for (char element : payload.toCharArray()) {
                payloadByte = (int) element;
                // System.out.println(element + ":" + Integer.toString(character));
                for (int i = 0; i < 8; i++) {
                    readByte = stream.read();
                    payloadBit = (payloadByte >> i) & 1;
                    newByte = (readByte & 0b11111110) | payloadBit;
                    stream.seek(pos);
                    stream.write(newByte);
                    pos++;
                }
            }

        } catch (IOException e) {
            return;
        }

        try {
            if(!isEnd) {
                FileUtils.copyFile(stegoFile, new File("./" + sendTo + "/Slika.bmp"));
            }else{
                FileUtils.copyFile(stegoFile, new File("./" + sendTo + "/" + Main.username + ".bmp"));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }


    }


    public static int locatePixelArray(File file) {
        try (FileInputStream stream = new FileInputStream(file)) {
            stream.skip(10);
            int location = 0;
            for (int i = 0; i < 4; i++) {
                location = location | (stream.read() << (4 * i));
            }
            return location;
        } catch (IOException e) {
            return -1;
        }
    }


    public static String decode(File carrier) {
        int start = locatePixelArray(carrier);
        try (FileInputStream stream = new FileInputStream(carrier)) {
            stream.skip(start);

            for (int i = 0; i < 32; i++) {
                if ((stream.read() & 1) != 0) {
                    return "Picture has not been encoded!!!";
                }
            }

            String result = "";
            int character;
            while (true) {
                character = 0;
                for (int i = 0; i < 8; i++) {
                    character = character | ((stream.read() & 1) << i);
                }
                if (character == 0)
                    break;
                result += (char) character;
            }
            return result;
        } catch (IOException e) {
            return "IOException: " + e.getMessage();
        }
    }

    public static int charactersAvailable(File carrier) {
        return (int) (carrier.length() - locatePixelArray(carrier) + 32) / 8;
    }

}
