#include "netbuffer.h"
#include "mailuser.h"
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#define MAX_LINE_LENGTH 1024
#define SPLIT_ARGS_LENGTH 20

#define AUTH_STATE 1
#define TRANS_STATE 2
#define UPDT_STATE 3

static void handle_client(int fd);
void sendReply(int fd, char* message);
void sendError(int fd, char* error);
void sendStat(int fd, int msgCount, int mailListSize);
int verifyUser(char* stringToVerify);
int verifyUserAndPassword(char* userName, char* password);

int main(int argc, char *argv[]) {
  
    if (argc != 2) {
	fprintf(stderr, "Invalid arguments. Expected: %s <port>\n", argv[0]);
	return 1;
    }
  
    run_server(argv[1], handle_client);
  
    return 0;
}

void handle_client(int fd) {
  
    net_buffer_t nb = nb_create(fd, MAX_LINE_LENGTH);
// Initialize these pointers as NULL
    char* userBuf = NULL;
    char* prevCommand = NULL;
// The maillist of the current user (if there is a user in the transaction state)
    mail_list_t curUserList;
// Welcome message part
    sendReply(fd, "POP3 server is ready to interact here!");

    int state = AUTH_STATE;
    int USERFlag = 0;

    while(1) {
        char recvbuf[MAX_LINE_LENGTH + 1];
// Read a single line from the socket and split it by white space
        if(nb_read_line(nb, recvbuf)) {
            char* splitCommand[SPLIT_ARGS_LENGTH];
            int argsCount = split(recvbuf, splitCommand);
            // QUIT
            if(splitCommand[0] != NULL) {
                if(strcasecmp(splitCommand[0], "quit") == 0) {
                    if(argsCount != 1) {
                        sendError(fd, "Invalid syntax / order of commands");
                    } else if (state == AUTH_STATE){
                        sendReply(fd, "POP3 server signing off");
                        break; 
                    } else if (state == TRANS_STATE) {
                        int err = destroy_mail_list(curUserList);
                        if (err > 0) {
                            send_formatted(fd, "+ERR %d deleted messages not removed\r\n", err);
                        } else {
                          sendReply(fd, "POP3 server signing off");  
                        }
                        state = UPDT_STATE;
                        sendReply(fd, "POP3 server signing off");
                        break;
                    }
                    // NOOP 
                } else if(strcasecmp(splitCommand[0], "noop") == 0) {
                    if(argsCount != 1 || state != TRANS_STATE) {
                        sendError(fd, "Invalid syntax / order of commands");
                    } else {
                        sendReply(fd, "");
                    }
                    // USER
                } else if(strcasecmp(splitCommand[0], "user") == 0) {
                    if(argsCount != 2 || state != AUTH_STATE) {
                        sendError(fd, "Invalid syntax / order of commands");
                    } else {
                        if(verifyUser(splitCommand[1])) {
                            userBuf = strdup(splitCommand[1]);
                            USERFlag = 1;
                            send_formatted(fd, "+OK %s is a valid mailbox\r\n", userBuf);  
                        } else {
                            USERFlag = 0;
                            sendError(fd, "User does not exist");
                        }
                    }   
                // PASS: may only be given in the AUTHORIZATION state immediately after a successful USER command 
                } else if(strcasecmp(splitCommand[0], "pass") == 0) {
                    if(argsCount != 2 || state != AUTH_STATE || strcasecmp(prevCommand, "user") != 0 || !USERFlag) {
                        sendError(fd, "Invalid syntax / order of commands");
                    } else {
                        if(verifyUserAndPassword(userBuf, splitCommand[1])) {
                            state = TRANS_STATE;
                            sendReply(fd, "mailbox ready");
                            curUserList = load_user_mail(userBuf);
                        } else {
                            sendError(fd, "invalid password");  
                        }
                    } 
                    // STAT 
                } else if (strcasecmp(splitCommand[0], "stat") == 0) {
                    if (argsCount != 1 || state != TRANS_STATE ) {
                        sendError(fd, "Invalid syntax / order of commands");
                    } else {
                        int msgCount = get_mail_count(curUserList, 0);
                        int sizeOfMailDrop = get_mail_list_size(curUserList);
                        sendStat(fd, msgCount, sizeOfMailDrop);
                    }
                    // LIST
                } else if (strcasecmp(splitCommand[0], "list") == 0) {
                        int msgCount = get_mail_count(curUserList, 0);
                        int sizeOfMailDrop = get_mail_list_size(curUserList);
                    if (argsCount > 2 || state != TRANS_STATE ) {
                        sendError(fd, "Invalid syntax / order of commands");
                    } else if (argsCount == 1){
                        send_formatted(fd, "+OK %d messages (%d octets)\r\n", msgCount, sizeOfMailDrop);
                        for (int i = 0; i < get_mail_count(curUserList, 1); i++) {
                            if (get_mail_item(curUserList, i)) {
                               send_formatted(fd, "%d %d\r\n", i+1, (unsigned int)get_mail_item_size(get_mail_item(curUserList, i))); 
                            }
                        }
                        send_formatted(fd, ".\r\n");
                    } else {
                        int pos = strtol(splitCommand[1], NULL, 10);
                        if (pos == 0) {
                            sendError(fd, "Invalid argument for LIST");
                        } else {
                            mail_item_t item = get_mail_item(curUserList, pos - 1);
                            if (!item) {
                                sendError(fd, "The position is invalid or the message is marked as deleted");
                            } else {
                                sendStat(fd, pos , get_mail_item_size(item));
                            }
                        }
                    }
                    // DELE
                } else if (strcasecmp(splitCommand[0], "dele") == 0) {
                    if (argsCount != 2 || state != TRANS_STATE ) {
                        sendError(fd, "Invalid syntax / order of commands");
                    } else {
                        int pos = strtol(splitCommand[1], NULL, 10);
                        if (pos == 0) {
                            sendError(fd, "Invalid argument for DELE");
                        } else {
                            mail_item_t item = get_mail_item(curUserList, pos - 1);
                            if (!item) {
                                sendError(fd, "The position is invalid or the current message is marked as deleted");
                            } else {
                               mark_mail_item_deleted(item);
                               send_formatted(fd, "+OK message %d deleted\r\n", pos);
                            }
                        }
                    }
                    // RSET
                } else if (strcasecmp(splitCommand[0], "rset") == 0) {
                    if (argsCount != 1 || state != TRANS_STATE ) {
                        sendError(fd, "Invalid syntax / order of commands");
                    } else {
                        unsigned int msgRestoredCount = reset_mail_list_deleted_flag(curUserList);
                        send_formatted(fd, "+OK %d messages restored\r\n", msgRestoredCount);
                    }
                    // RETR
                } else if (strcasecmp(splitCommand[0], "retr") == 0) {
                    if (argsCount != 2 || state != TRANS_STATE ) {
                        sendError(fd, "Invalid syntax / order of commands");
                    } else {
                        int pos = strtol(splitCommand[1], NULL, 10);
                        if (pos == 0) {
                            sendError(fd, "Invalid argument for RETR");
                        } else {
                            mail_item_t item = get_mail_item(curUserList, pos - 1);
                            if (!item) {
                                sendError(fd, "The position is invalid or the current message is marked as deleted");
                            } else {
                                char msg[MAX_LINE_LENGTH];
                                send_formatted(fd, "+OK %d octets\r\n", (int) get_mail_item_size(item));
                                FILE *fp = get_mail_item_contents(item);
                                if (fp) {
                                   while ( fgets (msg, MAX_LINE_LENGTH, fp)!=NULL ) {
                                   send_formatted(fd, "%s", msg);
                                   } 
                                fclose(fp);
                                }
                                send_formatted(fd, ".\r\n");
                            }
                        }
                    }
                } else {
                    sendError(fd, "Command unrecognized");
                }

                prevCommand = strdup(splitCommand[0]); // stores last command issued

            } else {
                sendError(fd, "Command unrecognized");
            }
        } else {
            break;
        }
    }
    // Free the heap, (avoid memory leak and dangling pointer)
    if (userBuf) {
       free(userBuf);
       userBuf = NULL; 
    }

    if (prevCommand) {
        free(prevCommand);
        prevCommand = NULL;
    }
    

    nb_destroy(nb);
    nb = NULL;
    close(fd);
    exit(0);
}

void sendReply(int fd, char* message) {
    send_formatted(fd, "+OK %s\r\n", message);
}

void sendError(int fd, char* error) {
    send_formatted(fd, "-ERR %s\r\n", error);
}

void sendStat(int fd, int msgCount, int mailListSize) {
    send_formatted(fd, "+OK %d %d\r\n", msgCount, mailListSize);
}


int verifyUser(char* stringToVerify) {
    if(stringToVerify == NULL) {
        return 0;
    } 
    return is_valid_user(stringToVerify, NULL);
}

int verifyUserAndPassword(char* userName, char* password) {
    if(password == NULL) {
        return 0;
    }
    return is_valid_user(userName, password);
}
