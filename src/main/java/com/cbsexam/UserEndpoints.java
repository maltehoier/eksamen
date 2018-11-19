package com.cbsexam;

import cache.UserCache;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import controllers.UserController;
import java.util.ArrayList;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import model.User;
import utils.Encryption;
import utils.Hashing;
import utils.Log;

@Path("user")
public class UserEndpoints {

    private static UserCache userCache = new UserCache();

    /**
     * @param idUser
     * @return Responses
     */
    @GET
    @Path("/{idUser}")
    public Response getUser(@PathParam("idUser") int idUser) {

        // Use the ID to get the user from the controller.
        User user = UserController.getUser(idUser);

        // TODO: Add Encryption to JSON: FIXED
        // Convert the user object to json in order to return the object
        String json = new Gson().toJson(user);
        json = Encryption.encryptDecryptXOR(json);

        // Return the user with the status code 200
        // TODO: What should happen if something breaks down?
        return Response.status(200).type(MediaType.APPLICATION_JSON_TYPE).entity(json).build();
    }
    //selv tilføjet. Sættes uden for metoden getProduct, fordi ellers ville der blive oprettet en ny cache hver gang

    /**
     * @return Responses
     */
    @GET
    @Path("/")
    public Response getUsers() {

        // Write to log that we are here
        Log.writeLog(this.getClass().getName(), this, "Get all users", 0);

        // Get a list of users
        ArrayList<User> users = userCache.getUsers(false); //har ændret i denne

        // TODO: Add Encryption to JSON: FIXED
        // Transfer users to json in order to return it to the user
        String json = new Gson().toJson(users);
        json = Encryption.encryptDecryptXOR(json);

        // Return the users with the status code 200
        return Response.status(200).type(MediaType.APPLICATION_JSON).entity(json).build();
    }

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createUser(String body) {

        // Read the json from body and transfer it to a user class
        User newUser = new Gson().fromJson(body, User.class);

        // Use the controller to add the user
        User createUser = UserController.createUser(newUser);


        // Get the user back with the added ID and return it to the user
        String json = new Gson().toJson(createUser);
        userCache.getUsers(true);

        // Return the data to the user
        if (createUser != null) {
            // Return a response with status 200 and JSON as type
            return Response.status(200).type(MediaType.APPLICATION_JSON_TYPE).entity(json).build();
        } else {
            return Response.status(400).entity("Could not create user").build();
        }
    }

    // TODO: Make the system able to login users and assign them a token to use throughout the system.
    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response loginUser(String body) {

        User signedInUser = new Gson().fromJson(body, User.class);
        Hashing hashing = new Hashing();

        User userFromDB = UserController.getUserByEmail(signedInUser.getEmail());
        String json = new Gson().toJson(userFromDB);


        // Return a response with status 200 and JSON as type
        if (userFromDB.getEmail() != null && signedInUser.getEmail().equals(userFromDB.getEmail()) && hashing.hashWithSalt(signedInUser.getPassword()).equals(userFromDB.getPassword())) {
            return Response.status(200).entity("Signed in" + json).build();

        } else
            return Response.status(400).entity("Password or username is wrong").build();
    }

    // TODO: Make the system able to delete users. FIXED
    //selv tilføjet
    @POST
    @Path("/delete/{delete}")
    public Response deleteUser(@PathParam("delete") int idToDelete) {
        UserController.deleteUser(idToDelete);
        // selv tilføjet så det ikke hentes fra den uopdaterede cach //DEMO!
        userCache.getUsers(true);

        if (UserController.getUser(idToDelete) != null) {
            return Response.status(200).entity("User ID " + idToDelete + " deleted").build();


        } else
            //Hvis man ikke kan få slettet en bruger. Fx hvis brugeren ikke findes
            return Response.status(400).entity("Unable to delete user").build();
    }

    // TODO: Make the system able to update users
    //husk at fixe så den kan give den rigtige fejlmeddelelse
    @POST
    @Path("/update/{update}/{token}")
    public Response updateUser(@PathParam("update") int idToUpdate, @PathParam("token") String token, String body) {


        //Algorithm algorithm = Algorithm.HMAC256("malte");
        //JWTVerifier verifier = JWT.require(algorithm)
          //      .withIssuer("auth0")
            //    .build(); //Reusable verifier instance
        //DecodedJWT jwt = verifier.verify(token);

        DecodedJWT jwt = JWT.decode(token);


        if (jwt.getClaim("id").asInt() == idToUpdate) {

            User updates = new Gson().fromJson(body, User.class);
            User currentUser = UserController.getUser(idToUpdate);


            //sørger for at kun personer med en token kan updatere infomation, fordi så er vi sikker på,
            //at de er logget ind


            //if (updates.getToken())

            if (updates.getFirstname() == null) {
                updates.setFirstname(currentUser.getFirstname());
            }

            if (updates.getLastname() == null) {
                updates.setLastname(currentUser.getLastname());
            }
            if (updates.getEmail() == null) {
                updates.setEmail(currentUser.getEmail());
            }

            //metode til at ændre password

            UserController.updateUser(idToUpdate, updates);
            if (UserController.getUser(idToUpdate) != null) {
                userCache.getUsers(true);

            }

            return Response.status(200).entity("The user with the ID " + idToUpdate + " is now updated").build();

        } else
            // Return a response with status 200 and JSON as type
            return Response.status(400).entity("Could not update user details").build();



    }

}

