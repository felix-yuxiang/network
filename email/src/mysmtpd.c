#include "netbuffer.h"
#include "mailuser.h"
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <ctype.h>

#define MAX_LINE_LENGTH 1024
#define SPLIT_ARGS_LENGTH 20
#define MAX_RECEIVERS 50

static void handle_client(int fd);
void sendReply(int fd, int replyNo);
void sendError(int fd, int errorNo);
int verifyUser(char* stringToVerify);
void buildMessage(int fd, net_buffer_t* nb, user_list_t receiverList);

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

    struct utsname my_uname;
    uname(&my_uname);

    char senderBuf[MAX_LINE_LENGTH + 1]; // Records sender
    user_list_t receiverList = create_user_list(); // Records receivers
    
    int EHLOFlag = 0;  // Records whether EHLO has been called
    int MAILFlag = 0;  // Records whether MAIL has been called
    int RCPTFlag = 0;  // Records whether RCPT has been called
    
    send_formatted(fd, "220 %s Simple Mail Transfer Service Ready\r\n", my_uname.nodename);

    while(1) {
        
        char recvbuf[MAX_LINE_LENGTH + 1];

        if(nb_read_line(nb, recvbuf)) {

            char* splitCommand[SPLIT_ARGS_LENGTH];
            int argsCount = split(recvbuf, splitCommand);

            if(splitCommand[0] != NULL) {
                if(strcasecmp(splitCommand[0], "quit") == 0) {
                    if(argsCount != 1) {
                        sendError(fd, 501);
                    } else {
                        send_formatted(fd, "221 Bye\r\n");
                        break;
                    }
                } else if(strcasecmp(splitCommand[0], "ehlo") == 0) {
                    if(argsCount != 2) {
                        sendError(fd, 501);
                    } else {
                        EHLOFlag = 1;
                        senderBuf[0] = '\0';
                        destroy_user_list(receiverList);
                        receiverList = create_user_list();
                        MAILFlag = 0;
                        RCPTFlag = 0;
                        send_formatted(fd, "250 %s is here\r\n", my_uname.nodename);
                    }
                } else if(strcasecmp(splitCommand[0], "helo") == 0) {
                    if(argsCount != 2) {
                        sendError(fd, 501);
                    } else {
                        send_formatted(fd, "250 %s is here\r\n", my_uname.nodename);
                    }
                } else if(strcasecmp(splitCommand[0], "noop") == 0) {
                    if(argsCount != 1) {
                        sendError(fd, 501);
                    } else {
                        sendReply(fd, 250);
                    }
                } else if(strcasecmp(splitCommand[0], "vrfy") == 0) {
                    if(argsCount != 2) {
                        sendError(fd, 501);
                    } else if(verifyUser(splitCommand[1])) {
                        sendReply(fd, 250);
                    } else {
                        send_formatted(fd, "550 Did not verify successfully\r\n");
                    }
                } else if (strcasecmp(splitCommand[0], "mail") == 0) {
                    if(argsCount <= 1) {
                        sendError(fd, 501);
                    } else {
                        char *firstChars, *restChars;
                        firstChars = strtok(splitCommand[1], ":");
                        restChars = strtok(NULL, ":");
                        if(!firstChars || strcasecmp(firstChars, "from") != 0 || 
                            restChars[0] != '<' || restChars[strlen(restChars) - 1] != '>') {
                            sendError(fd, 501);
                        } else {
                            char* extracted = strtok(restChars, "<>");
                            dlog("%s", extracted);
                            if(extracted) {
                                if(EHLOFlag) {
                                    strcpy(senderBuf, extracted);
                                    MAILFlag = 1;
                                    sendReply(fd, 250);
                                } else {
                                    sendError(fd, 503);
                                }
                            } else {
                                sendError(fd, 501);
                            }
                        }
                    }
                } else if (strcasecmp(splitCommand[0], "rcpt") == 0) {
                    if(argsCount <= 1) {
                        sendError(fd, 501);
                    } else {
                        char *firstChars, *restChars;
                        firstChars = strtok(splitCommand[1], ":");
                        restChars = strtok(NULL, ":");
                        if(!firstChars || strcasecmp(firstChars, "to") != 0 || 
                            restChars[0] != '<' || restChars[strlen(restChars) - 1] != '>') {
                            sendError(fd, 501);
                        } else {
                            char* extracted = strtok(restChars, "<>");
                            // dlog("%s", extracted);
                            if(extracted) {
                                if(MAILFlag) {
                                    if(verifyUser(extracted)) {
                                        add_user_to_list(&receiverList, extracted);
                                        RCPTFlag = 1;
                                        sendReply(fd, 250);
                                    } else {
                                        send_formatted(fd, "550 No such user, %s\r\n", extracted);
                                    }
                                } else {
                                    sendError(fd, 503);
                                }
                            } else {
                                sendError(fd, 501);
                            }
                        }
                    }                    
                } else if (strcasecmp(splitCommand[0], "data") == 0) {
                    if(argsCount != 1) {
                        sendError(fd, 501);
                    } else if(!MAILFlag || !RCPTFlag) {
                        sendError(fd, 503);
                    } else {
                        send_formatted(fd, "354 Start mail input; end with <CRLF>.<CRLF>\r\n");
                        buildMessage(fd, &nb, receiverList);
                    }
                } else if (strcasecmp(splitCommand[0], "rset") == 0) {
                    if(argsCount != 1) {
                        sendError(fd, 501);
                    } else {
                        senderBuf[0] = '\0';
                        destroy_user_list(receiverList);
                        receiverList = create_user_list();
                        MAILFlag = 0;
                        RCPTFlag = 0;
                        sendReply(fd, 250);
                    }
                } else if (strcasecmp(splitCommand[0], "help") == 0 || strcasecmp(splitCommand[0], "expn") == 0) {
                    sendError(fd, 502);
                } else {
                    sendError(fd, 500);    
                }
            } else {
                sendError(fd, 500);
            }
        } else {
            break;
        }

    }
    destroy_user_list(receiverList);
    nb_destroy(nb);
    close(fd);
    exit(0);
}

void sendReply(int fd, int replyNo) {
    if(replyNo == 250) {
        send_formatted(fd, "250 OK\r\n");
    }
}

void sendError(int fd, int errorNo) {
    if(errorNo == 500) {
        send_formatted(fd, "500 Syntax error, command unrecognized\r\n");
    } else if (errorNo == 501) {
        send_formatted(fd, "501 Syntax error in parameters or arguments\r\n");
    } else if (errorNo == 502) {
        send_formatted(fd, "502 Command not implemented\r\n");
    } else if (errorNo == 503) {
        send_formatted(fd, "503 Bad sequence of commands\r\n");
    }
}

int verifyUser(char* stringToVerify) {
    if(stringToVerify == NULL) {
        return 0;
    } 
    return is_valid_user(stringToVerify, NULL);

}

void buildMessage(int fd, net_buffer_t* nb, user_list_t receiverList) {
    char fileName[20] = "mailContent_XXXXXX";
    int tmpFilefd = mkstemp(fileName);
    if(tmpFilefd) {
        while(1) {
            char linedata[MAX_LINE_LENGTH + 1];
            char* linebuf = linedata;
            if(nb_read_line(*nb, linebuf)) {
                if(strcmp(linebuf, ".\r\n") == 0) {
                    save_user_mail(fileName, receiverList);
                    sendReply(fd, 250);
                    break;
                } else {
                    if(linebuf[0] == '.') {
                        linebuf++;
                    }
                    write(tmpFilefd, linebuf, strlen(linebuf));
                }
            } else {
                break;
            }
        }
    }
    close(tmpFilefd);
}
