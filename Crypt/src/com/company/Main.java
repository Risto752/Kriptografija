package com.company;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;

import org.apache.commons.io.FileUtils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class Main {

    public static boolean loggedIn = false;
    public static boolean loggedOut = false;
    public static ArrayList<String> startSent = new ArrayList<>();
    public static String delimiter =  "!@#%";


    public static String username;


    public static PublicKey publicKeyFriend; // vidjecemo dal ce trebat



    static {
        Security.addProvider(new BouncyCastleProvider());
    }



    public static void main(String[] args) throws Throwable{

        while(!loggedIn) {
            logIn();
        }

        Inbox myInbox = new Inbox(username);
        Inbox.username = username;


        myInbox.start();


        Scanner sc = new Scanner(System.in);

        System.out.println("Unesite zeljene komande: ");


        while(!loggedOut){


            String command = sc.nextLine();


            if(!command.contains(" ")){

                if(command.equals("show")){

                    showActiveUsers();


                }else if(command.equals("exit")){

                    loggedOut = true;

                }else{
                    System.out.println("Unjeli ste neispravnu komandu.");
                }



            }else{

                String[] parts = command.split(" ");

                if((parts.length == 3) && parts[0].equals("session")) {

                    String wantedUser = parts[1];


                    if (parts[2].equals("start")) {

                        if(!isActive(wantedUser)){

                            System.out.println("Korisnik " + wantedUser + " trenutno nije aktivan.");

                        }else{

                        boolean alreadySent = false;
                        boolean alreadyRecived = false;

                            for(String user : startSent){

                                if(user.equals(wantedUser)){

                                    System.out.println("Zahtjev za sesiju sa " + wantedUser + " ste vec poslali. Sacekajte odgovor.");
                                    alreadySent = true;
                                }



                            }

                            for(String user : Inbox.waitingForResponse){

                                if(user.equals(wantedUser)){

                                    System.out.println("Zahtjev za sesiju vam je vec stigao od korisnika" + wantedUser + ". Odgovorite mu sa ok ili no");
                                    alreadyRecived = true;
                                }





                            }

                            if(!alreadyRecived && !alreadySent){



                                    String message = "start_" + username;
                                    String digitalSignatureBase64 = digitalSignature(message);
                                    String encryptedBase64 = encryptRSA(wantedUser,message);



                                    String completeMessage = encryptedBase64 + delimiter + digitalSignatureBase64;

                                    Steganography.encode(new File("./Truth.bmp"), completeMessage, wantedUser,false);

                                    startSent.add(wantedUser);


                            }


                        }


                    }else if(parts[2].equals("ok")){

                        boolean userFound = false;

                        for(String user : Inbox.waitingForResponse){

                            if(user.equals(wantedUser)){


                                Random rand = new Random();

                                int randNumber = rand.nextInt(2);


                                if(randNumber == 0){

                                   SecretKey secretKey = genSymmetricKey("AES", wantedUser, 128);
                                   String algorithm = "AES/ECB/PKCS5Padding";
                                   Inbox.activeSessions.add(new Session(secretKey,algorithm, wantedUser));

                                   String ok = "ok";

                                   byte[] keyBytes = secretKey.getEncoded();

                                   String keyBase64 = Base64.toBase64String(keyBytes);

                                   String completeMessage = ok + delimiter + keyBase64 + delimiter + algorithm;

                                    String digSignatureBase64 = digitalSignature(completeMessage);

                                   String completeMessageBase64 = encryptRSA(wantedUser,completeMessage);

                                   sendMessage("" + username + ".message1", wantedUser,completeMessageBase64 + delimiter + digSignatureBase64);

                                    System.out.println("Uspjesno ste zapoceli sesiju sa " + wantedUser+ "! AES");


                                }else if(randNumber == 1){

                                  SecretKey secretKey = genSymmetricKey("DESede", wantedUser, 168);
                                  String algorithm = "DESede/ECB/PKCS5Padding";
                                  Inbox.activeSessions.add(new Session(secretKey,algorithm, wantedUser));

                                    String ok = "ok";

                                    byte[] keyBytes = secretKey.getEncoded();


                                    String keyBase64 = Base64.toBase64String(keyBytes);

                                    String completeMessage = ok + delimiter + keyBase64 + delimiter + algorithm;

                                    String digSignatureBase64 = digitalSignature(completeMessage);

                                    String completeMessageBase64 = encryptRSA(wantedUser,completeMessage);

                                    sendMessage("" + username + ".message1", wantedUser,completeMessageBase64 + delimiter + digSignatureBase64);

                                    System.out.println("Uspjesno ste zapoceli sesiju sa " + wantedUser+ "! 3DES");
                                }


                                userFound = true;

                            }


                        }

                        if(!userFound){

                            System.out.println("Korisnik " + wantedUser + " ne ocekuje ok. Da biste zapoceli razgovor unesite: session " + wantedUser + " start");

                        }else{
                            Inbox.waitingForResponse.remove(wantedUser);
                        }





                    }else if(parts[2].equals("no")) {

                        boolean userFound = false;

                        for(String user : Inbox.waitingForResponse){

                            if(user.equals(wantedUser)){

                                String digitalSignatureBase64 = digitalSignature("no");
                                String encryptedBase64 =  encryptRSA(wantedUser,"no");

                                String completeMessage = encryptedBase64 + delimiter + digitalSignatureBase64;

                                sendMessage(username+".message2",wantedUser, completeMessage );


                                System.out.println("Na vas zahtjev sesija nece biti uspostavljena sa korisnikom " + wantedUser+ ".");
                                userFound = true;

                            }


                        }



                        if(!userFound){

                            System.out.println("Korisnik " + wantedUser + " ne ocekuje poruku no definisano protokolom.");

                        }else{

                            Inbox.waitingForResponse.remove(wantedUser);

                        }


                    }else if(parts[2].equals("end")) {

                        boolean usrFound = false;

                        Session sessionToDelete = null;

                        for(Session x : Inbox.activeSessions) {


                            if(wantedUser.equals(x.friend)) {

                                String message = "kraj";
                                String digitalSignatureBase64 = digitalSignature(message);


                                Cipher cipher = Cipher.getInstance(x.algorithm);
                                cipher.init(Cipher.ENCRYPT_MODE, x.secretKey);
                                byte[] cipherText = cipher.doFinal(message.getBytes());

                                String cipherTextBase64 = Base64.toBase64String(cipherText);

                                String completeMessage = cipherTextBase64 + delimiter + digitalSignatureBase64;

                                Steganography.encode(new File("./Truth.bmp"), completeMessage, wantedUser, true);

                                usrFound = true;
                                sessionToDelete = x;
                                System.out.println("Uspjesno ste prekinuli sesiju sa korisnikom " + wantedUser + ".");

                                if (startSent.contains(wantedUser)) {

                                    startSent.remove(wantedUser);

                                }


                            }

                        }

                        if(!usrFound){

                            System.out.println("Ne mozete raskinuti sesiju koju niste uspostavili.");

                        }else{

                            Inbox.activeSessions.remove(sessionToDelete);

                        }




                    }else{

                        System.out.println("Unjeli ste neispravnu komandu.");

                    }




                }else if(parts.length >= 3 && parts[0].equals("chat")){

                    String wantedUser = parts[1];

                    if(!isActive(wantedUser)){

                    }else{

                        boolean usrFound = false;

                        for(Session x : Inbox.activeSessions) {


                            if(x.friend.equals(wantedUser)) {

                                usrFound = true;

                                String clearText = "";

                                for (int i = 2; i < parts.length; i++) {

                                    clearText = clearText.concat(parts[i]);
                                    clearText = clearText.concat(" ");


                                }

                                String digSignatureBase64 = digitalSignature(clearText);
                                Cipher cipher = Cipher.getInstance(x.algorithm);
                                cipher.init(Cipher.ENCRYPT_MODE, x.secretKey);
                                byte[] cipherText = cipher.doFinal(clearText.getBytes());

                                String cipherTextBase64 = Base64.toBase64String(cipherText);

                                String completeMessage = cipherTextBase64 + delimiter + digSignatureBase64;

                                sendMessage(username,wantedUser, completeMessage);


                            }

                        }

                        if(!usrFound){

                            System.out.println("Morate prvo uspostaviti sesiju sa korisnikom " + wantedUser);

                        }


                    }


                }else{

                    System.out.println("Unjeli ste neispravnu komandu.");

                }

            }

        }

        endAllActiveSessions();

        logOut();

    }

    public static void endAllActiveSessions() throws Throwable{

        for(Session x : Inbox.activeSessions) {

                String message = "kraj";
                String digitalSignatureBase64 = digitalSignature(message);

                Cipher cipher = Cipher.getInstance(x.algorithm);
                cipher.init(Cipher.ENCRYPT_MODE, x.secretKey);
                byte[] cipherText = cipher.doFinal(message.getBytes());

                String cipherTextBase64 = Base64.toBase64String(cipherText);

                String completeMessage = cipherTextBase64 + delimiter + digitalSignatureBase64;

                Steganography.encode(new File("./Truth.bmp"), completeMessage, x.friend, true);


                System.out.println("Uspjesno ste prekinuli sesiju sa korisnikom " + x.friend + ".");


        }



    }



    public static boolean checkCertificateValidity(String name) throws Throwable{

        boolean certSignedByCA = false;
        boolean certValid = false;
        boolean crlSignedByCA = false;
        boolean isCertRevoked = true;

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream finStream = new FileInputStream("./PKI/rootca.pem");
        X509Certificate caCertificate = (X509Certificate)cf.generateCertificate(finStream);

        FileInputStream userStream = new FileInputStream("./PKI/" + name);
        X509Certificate userCertificate = (X509Certificate)cf.generateCertificate(userStream);

        FileInputStream crlStream = new FileInputStream("./PKI/lista.pem");
        X509CRL crl = (X509CRL)cf.generateCRL(crlStream);

        try{

            userCertificate.verify(caCertificate.getPublicKey());
            certSignedByCA = true;

        }catch(Exception e){
            throw new CertificateException("Certificate not trusted",e);
        }



        try{

            userCertificate.checkValidity();
            certValid = true;

        }catch(Exception e){
            throw new CertificateException("Certificate not trusted. It has expired",e);
        }

        try{

           crl.verify(caCertificate.getPublicKey());
            crlSignedByCA = true;

        }catch (Exception e){

            e.printStackTrace();
        }


          isCertRevoked = crl.isRevoked(userCertificate);


        return certSignedByCA && certValid && crlSignedByCA && !isCertRevoked;



    }




    public static String digitalSignature(String message) throws Throwable{

        Signature signature = Signature.getInstance("SHA256WithRSA");
        SecureRandom secureRandom = new SecureRandom();
        signature.initSign(Inbox.loadPrivateKey(username), secureRandom);

        byte[] data = message.getBytes();
        signature.update(data);
        byte[] digitalSignature = signature.sign();

        return Base64.toBase64String(digitalSignature);

    }



    public static SecretKey genSymmetricKey(String algorithm, String wantedUser, int keysize) throws Throwable{


        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(keysize, secureRandom);


        return keyGenerator.generateKey();

    }




    public static String encryptRSA(String name, String clearText) throws Throwable{


        if(checkCertificateValidity(name)) {

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            publicKeyFriend = loadPublicKey(name);
            cipher.init(Cipher.ENCRYPT_MODE, publicKeyFriend);
            byte[] encrypted = cipher.doFinal(clearText.getBytes());


            return Base64.toBase64String(encrypted);
        }else{

            return name;
        }

    }





    public static PublicKey loadPublicKey(String name){


        PublicKey publicKey = null;

        try {
            String publicKeyPEM = FileUtils.readFileToString(new File("./PKI/private/" + name + "Pub.key"), StandardCharsets.UTF_8);

            publicKeyPEM = publicKeyPEM
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");


            byte[] publicKeyDER = Base64.decode(publicKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
             publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDER));




        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();

        }

      return publicKey;


    }



    public static boolean isActive(String name){

        try (BufferedReader br = new BufferedReader(new FileReader("aktivniKorisnici.txt"))) {
            String user;
            while ((user = br.readLine()) != null) {

                if(!user.equals(username)){
                    if(user.equals(name))
                        return true;
                }

            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Zahtjevani korisnik je trenutno neaktivan");
        return false;


    }

    public static void showActiveUsers(){

        System.out.println("Prikaz trenutno aktivnih korisnika: ");

        try (BufferedReader br = new BufferedReader(new FileReader("aktivniKorisnici.txt"))) {
            String user;
            while ((user = br.readLine()) != null) {

                if(!user.equals(username)){
                    System.out.println(user);
                }

            }
        } catch (IOException e) {
            e.printStackTrace();
        }



    }


    public static void logOut(){

        ArrayList<String> list = new ArrayList<>();

        try (BufferedReader br = new BufferedReader(new FileReader("aktivniKorisnici.txt"))) {
            String user;
            while ((user = br.readLine()) != null) {
                if(!user.equals(username)) {
                    list.add(user);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

       clear();

        for(String user : list){

            setActive(user,true);

        }

    System.out.println(username + " uspjesno ste se odjavili sa sistema");


    }


    public static void clear(){
        try (PrintWriter pw = new PrintWriter(new FileWriter("aktivniKorisnici.txt", false))) {
            pw.print("");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }



    public static void setActive(String user, boolean append){

        try (PrintWriter pw = new PrintWriter(new FileWriter("aktivniKorisnici.txt", append))) {

            pw.println(user);


        } catch (IOException e) {
            e.printStackTrace();
        }


    }


    public static void logIn(){

        Scanner scanner = new Scanner(System.in);

        String password;

        System.out.print("Unesite korisnicko ime: ");
        username = scanner.nextLine();
        System.out.print("Unesite lozinku: ");
        password = scanner.nextLine();


        try (BufferedReader br = new BufferedReader(new FileReader("nalozi.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {

                String[] parts = line.split("_");



                if(parts[0].equals(username)){

                    byte[] data = password.getBytes();
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
                    byte[] digest = messageDigest.digest(data);

                    if(parts[1].equals(new String(Base64.encode(digest)))){


                        System.out.println(username + " uspjesno ste se ulogovali na sistem.");
                        loggedIn = true;

                        setActive(username, true);

                        showActiveUsers();

                        return;

                    }

                }



            }
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }

        System.out.println("Neuspjesan login");

    }



    public static void sendMessage(String filename,String sendTo,String base64Message) throws Throwable{


         FileUtils.writeByteArrayToFile(new File("./"+ sendTo+ "/" + filename), base64Message.getBytes());


    }




}
