package controllers;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import model.User;
import utils.Hashing;
import utils.Log;

public class UserController {


  private static DatabaseController dbCon;

  public UserController() {
    dbCon = new DatabaseController();
  }

  public static User getUser(int id) {

    // Check for connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build the query for DB
    String sql = "SELECT * FROM user where id=" + id;

    // Actually do the query
    ResultSet rs = dbCon.query(sql);
    User user = null;

    try {
      // Get first object, since we only have one
      if (rs.next()) {
        user =
            new User(
                rs.getInt("id"),
                rs.getString("first_name"),
                rs.getString("last_name"),
                rs.getString("password"),
                rs.getString("email"));

        //Selv tilføjet:
        Algorithm algorithm = Algorithm.HMAC256("Malte");
        //opretter en token. Så man kan finde et ID ud fra en token
        String token = JWT.create().withClaim("id", user.getId()).sign(algorithm);
        user.setToken(token);


        // return the create object
        return user;
      } else {
        System.out.println("No user found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return null
    return user;
  }

  /**
   * Get all users in database
   *
   * @return
   */
  public static ArrayList<User> getUsers() {

    // Check for DB connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build SQL
    String sql = "SELECT * FROM user";

    // Do the query and initialyze an empty list for use if we don't get results
    ResultSet rs = dbCon.query(sql);
    ArrayList<User> users = new ArrayList<User>();

    try {
      // Loop through DB Data
      while (rs.next()) {
        User user =
            new User(
                rs.getInt("id"),
                rs.getString("first_name"),
                rs.getString("last_name"),
                rs.getString("password"),
                rs.getString("email"));

        // Add element to list
        users.add(user);
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return the list of users
    return users;
  }

  public static User createUser(User user) {

    Hashing hashing = new Hashing(); //selv tilføjet

    // Write in log that we've reach this step
    Log.writeLog(UserController.class.getName(), user, "Actually creating a user in DB", 0);

    // Set creation time for user.
    user.setCreatedTime(System.currentTimeMillis() / 1000L);

    // Check for DB Connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Insert the user in the DB
    // TODO: Hash the user password before saving it. FIXED
    int userID = dbCon.insert(
        "INSERT INTO user(first_name, last_name, password, email, created_at) VALUES('"
            + user.getFirstname()
            + "', '"
            + user.getLastname()
            + "', '"
            + hashing.hashWithSalt(user.getPassword()) //selv tilføjet redigeret væk fra "user.getPassword"
            + "', '"
            + user.getEmail()
            + "', "
            + user.getCreatedTime()
            + ")");

    if (userID != 0) {
      //Update the userid of the user before returning
      user.setId(userID);
    } else{
      // Return null if user has not been inserted into database
      return null;
    }

    // Return user
    return user;
  }


  //Hele denne metode er selv tilføjet
  //Method that delete a user from the database

  public static void deleteUser(int id) {
    if(dbCon == null) {
      dbCon = new DatabaseController();
    }

    String sql = "DELETE FROM user WHERE id=" + id;

    dbCon.deleteUser(sql);
  }
  public static void updateUser(int id, User updates){
    // tjekker om der er forbindelse til DB
    if(dbCon==null){
      dbCon=new DatabaseController();
    }

    //selv tilføjet if statement

      String sql = "UPDATE user set first_name = '" + updates.getFirstname() + "', last_name='" + updates.getLastname() + "', email= '" + updates.getEmail() + "' WHERE id=" + id;

      dbCon.updateUser(sql);
    }


  public static User getUserByEmail(String userEmail)  {

    if(dbCon==null){
      dbCon=new DatabaseController();
    }

    String sql = "SELECT * FROM user WHERE email = '" + userEmail + "'";

    ResultSet rs =  dbCon.query(sql);
    User user = null;

    try {

      if (rs.next()) {
        user =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email"));

        //Selv tilføjet:
        Algorithm algorithm = Algorithm.HMAC256("Malte");
        //opretter en token. Så man kan finde et ID ud fra en token
        String token = JWT.create().withClaim("id", user.getId()).sign(algorithm);
        user.setToken(token);



        // return the create object
        return user;
      } else {
        System.out.println("No user found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return null
    return user;
  }
}
