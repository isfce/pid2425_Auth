package main;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class GenerateChallenge {

  public static void main(String[] args) {
    String verifier = "ELtGWHUqGJpG7SXWOvih2BmgKwBI1boLfEQWVTeyrMA";
    System.out.println(generateChallenge(verifier));
  }

  public static String generateChallenge(String verifier) {
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      byte [] digested = messageDigest.digest(verifier.getBytes());
      String codeChallenge = Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(digested);

      return codeChallenge;
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
