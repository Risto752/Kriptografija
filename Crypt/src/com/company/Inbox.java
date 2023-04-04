package com.company;


import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;


import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.OVERFLOW;


public class Inbox extends Thread {



    public static String username;
    public static PrivateKey myPrivateKey;
    private String dirName;
    public static ArrayList<String> waitingForResponse = new ArrayList<>();
    public static ArrayList<Session> activeSessions = new ArrayList<>();



    public Inbox(String dirName){

        this.dirName = dirName;
        setDaemon(true);
    }



    public void run(){


        try {

            WatchService watcher = FileSystems.getDefault().newWatchService();
            Path dir = Paths.get("./" + dirName);

             dir.register(watcher,ENTRY_CREATE);

            while(true){

               WatchKey key;

               key = watcher.take();

               Thread.sleep(1000);

                for (WatchEvent<?> event: key.pollEvents()) {

                    WatchEvent.Kind<?> kind = event.kind();

                    if (kind == OVERFLOW) {
                        continue;
                    }

                    WatchEvent<Path> ev = (WatchEvent<Path>)event;
                    Path filename = ev.context();
                    Path filePath = Paths.get("./" + dirName +"/" + filename.toString());

                    String recivedFrom = "";


                        if(filename.toString().equals("Slika.bmp")){

                            String completeMessage = Steganography.decode(new File("./"+ username + "/" + filename.toString()));

                            String[] parts = completeMessage.split("!@#%");

                            String encryptedMessageBase64 = parts[0];
                            String digitalSignatureBase64 = parts[1];




                            String pom = decryptRSA(encryptedMessageBase64);
                            String[] pomParts = pom.split("_");
                            recivedFrom = pomParts[1];


                            if(verifySignature(digitalSignatureBase64,recivedFrom,pom)){


                                System.out.println(username + " korisnik " + recivedFrom + " zeli da zapocne sesiju sa vama.");
                                System.out.println("Da bi ste zapoceli sesiju posaljite posaljite mu 'session " + recivedFrom +" ok'.");
                                waitingForResponse.add(recivedFrom);

                                filePath.toFile().delete();

                            }else{

                                System.out.println("Neuspjesno validiran digitalni potpis;");


                            }





                        }else if(filename.toString().endsWith(".message1")) {


                            String[] split = filename.toString().split(".message1");
                            recivedFrom = split[0];
                          byte[] wholeFile = Files.readAllBytes(filePath);

                          String wholeFileBase64 = new String(wholeFile);

                          String[] parts = wholeFileBase64.split(Main.delimiter);
                          String completeMessageBase64 = parts[0];
                          String digSignatureBase64 = parts[1];


                          String completeMessage = decryptRSA(completeMessageBase64);


                            if(verifySignature(digSignatureBase64,recivedFrom,completeMessage)){


                                String[] components =  completeMessage.split(Main.delimiter);
                                String base64Key = components[1];
                                String algorithm = components[2];

                                String[] algorithmSplit = algorithm.split("/");

                                if(algorithmSplit[0].equals("AES")) {

                                    byte[] decodedKey = Base64.decode(base64Key);
                                    SecretKey originalKey = new SecretKeySpec(decodedKey,0,decodedKey.length,"AES");

                                    activeSessions.add(new Session(originalKey, algorithm, recivedFrom));

                                    System.out.println("Uspostavljena sesija sa korisnikom " + recivedFrom +"! AES");
                                }else{

                                    byte[] decodedKey = Base64.decode(base64Key);
                                    SecretKey originalKey = new SecretKeySpec(decodedKey,0,decodedKey.length,"DESede");

                                    activeSessions.add(new Session(originalKey, algorithm, recivedFrom));

                                    System.out.println("Uspostavljena sesija sa korisnikom " + recivedFrom +"! 3DES");


                                }

                                System.out.println(username + " korisnik "+ recivedFrom + " je prihvatio vas zahtjev za pocetak sesije mozete poceti sa dopisivanjem."  );


                                filePath.toFile().delete();
                            }else{

                                System.out.println("Neuspjesno validiran digitalni potpis;");


                            }


                        }else if(filename.toString().endsWith(".message2")){

                            String[] parts = filename.toString().split(".message2");
                            recivedFrom = parts[0];
                            byte[] wholeFile = Files.readAllBytes(filePath);
                            String wholeFileBase64 = new String(wholeFile);

                            String[] split = wholeFileBase64.split(Main.delimiter);

                            String encryptedBase64 = split[0];
                            String digSignatureBase64 = split[1];

                            String completeMessage = decryptRSA(encryptedBase64);

                            if(verifySignature(digSignatureBase64,recivedFrom,completeMessage)){

                                if(completeMessage.equals("no")){


                                    System.out.println("Korisnik " + recivedFrom + " trenutno ne zeli da uspostavi sesiju sa vama.");

                                    Main.startSent.remove(recivedFrom);

                                    filePath.toFile().delete();
                                }



                            }else{

                                System.out.println("Potpis nije verifikovan");

                            }




                        }else if(filename.toString().endsWith(".bmp")){

                            String completeMessage = Steganography.decode(new File("./"+ username + "/" + filename.toString()));

                            String[] split = filename.toString().split(".bmp");
                            recivedFrom = split[0];

                            String[] parts = completeMessage.split("!@#%");

                            String encryptedMessageBase64 = parts[0];
                            String digitalSignatureBase64 = parts[1];


                            String decryptedFinal = "";

                            Session sessionToDelete = null;

                            for(Session x : activeSessions){

                                if(recivedFrom.equals(x.friend)){


                                    Cipher cipher = Cipher.getInstance(x.algorithm);
                                    cipher.init(Cipher.DECRYPT_MODE, x.secretKey);
                                    byte[] clearText = cipher.doFinal(Base64.decode(encryptedMessageBase64));
                                    decryptedFinal = new String(clearText);
                                    sessionToDelete = x;

                                }


                            }

                            if(verifySignature(digitalSignatureBase64,recivedFrom,decryptedFinal)){


                                if(decryptedFinal.equals("kraj")){

                                    activeSessions.remove(sessionToDelete);

                                    if(Main.startSent.contains(recivedFrom)){

                                        Main.startSent.remove(recivedFrom);

                                    }


                                    System.out.println("Korisnik " + recivedFrom + " je prekinuo sesiju sa vama.");


                                }

                                filePath.toFile().delete();


                            }else{

                                System.out.println("Potpis nije verifikovan.");

                            }






                        }else{

                            recivedFrom = filename.toString();

                            byte[] wholeFile = Files.readAllBytes(filePath);
                            String completeMessageBase64 = new String(wholeFile);

                            String[] parts = completeMessageBase64.split(Main.delimiter);

                            String cipherTextBase64 = parts[0];
                            String digSignatureBase64 = parts[1];

                            String decryptedFinal = "";



                            for(Session x : activeSessions){

                                if(recivedFrom.equals(x.friend)){

                                    Cipher cipher = Cipher.getInstance(x.algorithm);
                                    cipher.init(Cipher.DECRYPT_MODE, x.secretKey);
                                    byte[] clearText = cipher.doFinal(Base64.decode(cipherTextBase64));
                                    decryptedFinal = new String(clearText);


                                }


                            }

                            if(verifySignature(digSignatureBase64,recivedFrom,decryptedFinal)){

                                System.out.println(recivedFrom + ": " + decryptedFinal);

                                filePath.toFile().delete();


                            }else{

                                System.out.println("Potpis nije verifikovan.");

                            }

                        }



                }

                boolean valid = key.reset();
                if (!valid) {
                    break;
                }



            }




        } catch (Throwable e) {
            e.printStackTrace();
        }


    }

    public static boolean verifySignature( String digitalSignatureBase64, String recivedFrom, String message) throws Throwable{


        if(Main.checkCertificateValidity(recivedFrom)) {

            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(Main.loadPublicKey(recivedFrom));
            signature.update(message.getBytes());

            return signature.verify(Base64.decode(digitalSignatureBase64));

        }else{

            return  false;

        }

    }



    public static String decryptRSA(String base64Message) throws Throwable {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        myPrivateKey = loadPrivateKey(username);
        cipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
        byte[] decrypted = cipher.doFinal(Base64.decode(base64Message));

        return new String(decrypted);


    }

    public static PrivateKey loadPrivateKey(String name){


        PrivateKey privateKey = null;

        try {
            String privateKeyPEM = FileUtils.readFileToString(new File( "./PKI/private/"+ username + ".pem"), StandardCharsets.UTF_8);
            privateKeyPEM = privateKeyPEM
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] privateKeyDER = Base64.decode(privateKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDER));

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return privateKey;

    }




}
