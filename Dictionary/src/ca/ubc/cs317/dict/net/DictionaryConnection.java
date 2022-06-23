package ca.ubc.cs317.dict.net;

import ca.ubc.cs317.dict.model.Database;
import ca.ubc.cs317.dict.model.Definition;
import ca.ubc.cs317.dict.model.MatchingStrategy;

import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.*;

/**
 * Created by Jonatan on 2017-09-09.
 */
public class DictionaryConnection {

    private static final int DEFAULT_PORT = 2628;

    private final Socket dictSocket;
    private BufferedReader readerDict;

    /**
     * Establishes a new connection with a DICT server using an explicit host and port number, and handles initial
     * welcome messages.
     *
     * @param host Name of the host where the DICT server is running
     * @param port Port number used by the DICT server
     * @throws DictConnectionException If the host does not exist, the connection can't be established, or the messages
     *                                 don't match their expected value.
     */
    public DictionaryConnection(String host, int port) throws DictConnectionException {
        try {
            dictSocket = new Socket(host, port);
            readerDict = new BufferedReader(new InputStreamReader(dictSocket.getInputStream()));
            Status initialStatus = Status.readStatus(readerDict);
//            Handles the welcome msg
            if (initialStatus.getStatusCode() != 220) { // text capabilities msg-id, usually a banner contains host name and DICT server version info.
                throw new DictConnectionException("The status code is not 220 which means the client's IP is not allowed to connect to the dict server.");
            } else if (host == null || host.isEmpty()) {
                throw new DictConnectionException("The host is null or an empty string");
            } else if (!dictSocket.isConnected()) {
                throw new DictConnectionException("The connection is not well connected!");
            }

//            System.out.println(initialStatus.getDetails());
        } catch (UnknownHostException e) {
            throw new DictConnectionException("IP address of the host cannot be determined.");
        } catch (IOException e) {
            throw new DictConnectionException("An I/O error occurs when creating the socket.");
        }
    }

    /**
     * Establishes a new connection with a DICT server using an explicit host, with the default DICT port number, and
     * handles initial welcome messages.
     *
     * @param host Name of the host where the DICT server is running
     * @throws DictConnectionException If the host does not exist, the connection can't be established, or the messages
     *                                 don't match their expected value.
     */
    public DictionaryConnection(String host) throws DictConnectionException {
        this(host, DEFAULT_PORT);
    }

    /**
     * Sends the final QUIT message and closes the connection with the server. This function ignores any exception that
     * may happen while sending the message, receiving its reply, or closing the connection.
     */
    public synchronized void close() {

        try {
//            IF the socket is previously closed, we cannot close again. But in that case we are pretty done.
            if (!dictSocket.isClosed()) {
                PrintWriter writerDict = new PrintWriter(dictSocket.getOutputStream(), true);
                writerDict.println("QUIT");

                Status curStatus = Status.readStatus(readerDict);
                if (curStatus.getStatusCode() == 221) { // Means Closing Connection
                    readerDict.close();
                    dictSocket.close();
                }
//          Print in the console to see if it is working correctly.
//                System.out.println(curStatus.getDetails());
            }

        } catch (IOException | DictConnectionException e) {
            e.printStackTrace();
        }
    }

    /**
     * Requests and retrieves all definitions for a specific word.
     *
     * @param word     The word whose definition is to be retrieved.
     * @param database The database to be used to retrieve the definition. A special database may be specified,
     *                 indicating either that all regular databases should be used (database name '*'), or that only
     *                 definitions in the first database that has a definition for the word should be used
     *                 (database '!').
     * @return A collection of Definition objects containing all definitions returned by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Collection<Definition> getDefinitions(String word, Database database) throws DictConnectionException {
        Collection<Definition> set = new ArrayList<>();
        String nameDB = database.getName();
//        Sending to the dict server in output stream, if the status code is not 150, we just return the empty set.
        try {
            PrintWriter writerDict = new PrintWriter(dictSocket.getOutputStream(), true);
            writerDict.println("DEFINE " + nameDB + " " + word);
            Status curStatus = Status.readStatus(readerDict);
            if (curStatus.getStatusCode() != 150) { // Indicates that n definitions retrieved - definitions follow
                return set;
            }
//            System.out.println(curStatus.getDetails());
        } catch (IOException e) {
            throw new DictConnectionException("Sending to the server command but gets interrupted unexpectedly.");
        }

        String serverToUser;
//          Parse whatever comes from the server in input stream, 250 means success which means we can break the infinite loop.
//        When parsing a sequence of lines terminated by a line containing only a period (.) symbol, do not include it in the definition
//        and use it as a condition to jump out the loop
        Collection<Definition> set1 = parseDictServerDefinition(set);
        if (set1 != null) return set1;
        return set;
    }


//    REQUIRE: The argument should be an empty set of definitions. Helper method.
//    MODIFIES: set
//    EFFECTS: parse the results from the dict server and create proper definitions to put in the set, throws DictConnection Exception when IO interrupts occur
    private Collection<Definition> parseDictServerDefinition(Collection<Definition> set) throws DictConnectionException {
        String serverToUser;
        try {
            while (true) {
                Status curStatus = Status.readStatus(readerDict);
                Definition def;
                if (curStatus.getStatusCode() == 250) { // Means that the status is OK
                    break;
                } else if (curStatus.getStatusCode() == 151) { // A new entry with database name and text follows
                    String[] info = DictStringParser.splitAtoms(curStatus.getDetails());
                    def = new Definition(info[0], info[1]);
                } else {
                    return set;
                }
                while (!(serverToUser = readerDict.readLine()).equals(".")) {
                    def.appendDefinition(serverToUser);
                }
                set.add(def);
            }
        } catch (IOException e) {
            throw new DictConnectionException("Receiving data from the server but gets interrupted unexpectedly.");
        }
        return null;
    }

    /**
     * Requests and retrieves a list of matches for a specific word pattern.
     *
     * @param word     The word whose definition is to be retrieved.
     * @param strategy The strategy to be used to retrieve the list of matches (e.g., prefix, exact).
     * @param database The database to be used to retrieve the definition. A special database may be specified,
     *                 indicating either that all regular databases should be used (database name '*'), or that only
     *                 matches in the first database that has a match for the word should be used (database '!').
     * @return A set of word matches returned by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Set<String> getMatchList(String word, MatchingStrategy strategy, Database database) throws DictConnectionException {
        Set<String> set = new LinkedHashSet<>();
        try {
            PrintWriter writerDict = new PrintWriter(dictSocket.getOutputStream(), true);
            writerDict.println("MATCH " + database.getName() + " " + strategy.getName() + " " + word);
            Status curStatus = Status.readStatus(readerDict);
            if (curStatus.getStatusCode() != 152) { // Indicates n matches found - text follows
                return set;
            }
//            System.out.println(curStatus.getDetails());
        } catch (IOException e) {
            throw new DictConnectionException("Sending to the server command but gets interrupted unexpectedly.");
        }
        extractMatchListFromDict(set);
        return set;
    }



//    REQUIRE: The set should consist of type String. Helper method.
//    MODIFIES: set
//    EFFECTS: parse the results from the dict server and put matching list words in the set, throws DictConnection Exception when IO interrupts occur
    private void extractMatchListFromDict(Set<String> set) throws DictConnectionException {
        String serverToUser;
        try {
            while (!(serverToUser = readerDict.readLine()).equals(".")) {
                String[] info = DictStringParser.splitAtoms(serverToUser);
                set.add(info[1]);
            }
            Status curStatus = Status.readStatus(readerDict);
            if (curStatus.getStatusCode() != 250) {
                throw new DictConnectionException("The query of Matching lists does not run/end successfully.");
            }

        } catch (IOException e) {
            throw new DictConnectionException("Receiving data from the server but gets interrupted unexpectedly.");
        }
    }


    /**
     * Requests and retrieves a map of database name to an equivalent database object for all valid databases used in the server.
     *
     * @return A map of Database objects supported by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Map<String, Database> getDatabaseList() throws DictConnectionException {
        Map<String, Database> databaseMap = new HashMap<>();

        try {
            PrintWriter writerDict = new PrintWriter(dictSocket.getOutputStream(), true);
            writerDict.println("SHOW DB");
            Status curStatus = Status.readStatus(readerDict);
            if (curStatus.getStatusCode() != 110) { // Indicates that n databases present - text follows
                return databaseMap;
            }

            System.out.println(curStatus.getDetails());
        } catch (IOException e) {
            throw new DictConnectionException("Sending to the server command but gets interrupted unexpectedly.");
        }

        extractDatabaseListFromDict(databaseMap);

        return databaseMap;
    }

//    REQUIRE: The databaseMap should consist of type Map<String name, Database>. Helper method.
//    MODIFIES: databaseMap
//    EFFECTS: parse the results from the dict server and put name and database in the databaseMap, throws DictConnection Exception when IO interrupts occur
    private void extractDatabaseListFromDict(Map<String, Database> databaseMap) throws DictConnectionException {
        String serverToUser;
        try {
            while (!(serverToUser = readerDict.readLine()).equals(".")) {
                String[] dbInfo = DictStringParser.splitAtoms(serverToUser);
                databaseMap.put(dbInfo[0], new Database(dbInfo[0], dbInfo[1]));
            }
            Status curStatus = Status.readStatus(readerDict);
            if (curStatus.getStatusCode() != 250) {
                throw new DictConnectionException("The query of DBList does not run/end successfully.");
            }
        } catch (IOException e) {
            throw new DictConnectionException("Receiving data from the server but gets interrupted unexpectedly.");
        }
    }

    /**
     * Requests and retrieves a list of all valid matching strategies supported by the server.
     *
     * @return A set of MatchingStrategy objects supported by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Set<MatchingStrategy> getStrategyList() throws DictConnectionException {
        Set<MatchingStrategy> set = new LinkedHashSet<>();

        try {
            PrintWriter writerDict = new PrintWriter(dictSocket.getOutputStream(), true);
            writerDict.println("SHOW STRATEGIES");
            Status curStatus = Status.readStatus(readerDict);
            if (curStatus.getStatusCode() != 111) { // Indicates that n strategies available - text follows
                return set;
            }

            System.out.println(curStatus.getDetails());
        } catch (IOException e) {
            throw new DictConnectionException("Sending to the server command but gets interrupted unexpectedly.");
        }
        extractStrategyListFromDict(set);

        return set;
    }

//    REQUIRE: The set should consist of type Matchingstrategy. Helper method.
//    MODIFIES: set
//    EFFECTS: parse the results from the dict server and put available Matching strategies in the set, throws DictConnection Exception when IO interrupts occur
    private void extractStrategyListFromDict(Set<MatchingStrategy> set) throws DictConnectionException {
        String serverToUser;
        try {
            while (!(serverToUser = readerDict.readLine()).equals(".")) {
                String[] matchingStrategiesInfo = DictStringParser.splitAtoms(serverToUser);
                set.add(new MatchingStrategy(matchingStrategiesInfo[0], matchingStrategiesInfo[1]));
            }
            Status curStatus = Status.readStatus(readerDict);
            if (curStatus.getStatusCode() != 250) {
                throw new DictConnectionException("The query of retrieving strategy list does not run/end successfully.");
            }
        } catch (IOException e) {
            throw new DictConnectionException("Receiving data from the server but gets interrupted unexpectedly.");
        }
    }

}
