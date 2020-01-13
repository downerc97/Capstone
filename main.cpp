/*
 * W7OSU Door-Lock Server
 * Created by Drake Vidkjer on 6/4/2018
 * Modified by Carson Downer
 * Version .5
 * Maintains a whitelist of accepted ID card numbers and responds to
 * querries from door locks.
 * This program will listen for UDP packets on port 25550 and responds 
 * to the packet with a simple yes or no, directed at the origin of the
 * packet.
 */
 
 /*
  * TODO:
  * Network
  */

#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <fstream>
#include <vector>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MSG_SIZE 250

using namespace std;

//function prototypes
void getTime(char* timeString);
void getWhitelist(vector <int> &whitelist);
bool testKey(vector <int> &whitelist, int keyTry);	//done
void network(vector <int> &whitelist);
void accLog(bool pass, int keyTry, sockaddr_in &clientIP);

//define global variables

int main(int argc, char* argv[])
{
	printf("W7OSU Door Lock Network Authentication Server\nCreated by Drake Vidkjer on 6/4/18\nModified by Drake Vidkjer on 6/5/18\nSystem Starting...\n");
	//define variables
	int i = 0;
	bool pass = false;
	//char doThis;
	vector <int> whitelist;
	
	//define network variables
	int port = -1;
	int socketfd = -1;
	sockaddr_in servaddr, cliaddr;
	socklen_t sockaddr_in_len = 0;
	int numRead = -1, numSent = -1;
	char data[MSG_SIZE];
	port = 25550;
	
	//setup network stuff
	if((socketfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
	    perror("socket");
	    exit(1);
    }
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
	
	//bind socket to port
	if(bind(socketfd,(sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
	    perror("bind");
	    exit(1);
    }
	
	
	printf("Getting Whitelist\n");
	
	//read the whitelist into the program
	getWhitelist(whitelist);
	
	//print the whielist
	printf("Whitelist:\n");
	for(i = 0; i < whitelist.size(); i++)
	{
		printf("%d\n", whitelist[i]);
	}
	
	//loop
	while(1)
	{
		printf("Waiting for request\n");
		
		//size of client address data stucture
		sockaddr_in_len = sizeof(cliaddr);
		
		//get data from client
		if((numRead = recvfrom(socketfd, data, sizeof(data), 0, 
            (sockaddr *)&cliaddr, &sockaddr_in_len)) < 0)
        {
            perror("recvfrom");
            exit(1);
        }
		
		i = atoi(data);
		printf("Data recieved: %d\n", i);
		
		//clear data array
		memset(&data, 0, sizeof(data));	
		
		//check value against stuff in array
		pass = testKey(whitelist, i);
		
		//write to the access log
		accLog(pass, i, cliaddr);
		
		//return 1 or 0 depending on if in whielist
		if(pass == true)
		{
			data[0] = '1';
			pass = false;
		}
		else
		{
			data[0] = '0';
			pass = false;
		}
		
		//send data pack to client
		if((numSent = sendto(socketfd, data, strlen(data)+1, 0,
            (sockaddr *)&cliaddr,sizeof(cliaddr))) < 0)
        {
            perror("sendto");
            exit(1);
        }
		
		/*
		printf("Type 'e' to exit\n");
		scanf("%c", &doThis);
		if(doThis == 'e')
		{
			exit(0);
		}
		else if(doThis == 'j')
		{
			//see if key is in whitelist
			printf("Enter key to check against whitelist: ");
			int j = 0;
			scanf("%d", &j);
			bool test = testKey(whitelist, j);
			if(test == true)
			{
				printf("Key is in array\n");
			}
		}
		
		//check for network requests
		
		
		doThis = ' ';
		*/
	}
	return 0;
}

//reads the whitelist into the program and also keeps trakc of the whitelist size
void getWhitelist(vector <int> &whitelist)
{
	//define local variables
	char timeString[24];
	char inString[10];
	int i = 0;
	
	//read in the whitelist 
	ifstream whiteRead("whitelist.txt");
	if(whiteRead.is_open())
	{
		//read each line of the whitelist file as another number in the whitelist
		while(!whiteRead.eof())
		{
			whiteRead.getline(inString, 10);
			whitelist.push_back(atoi(inString));
			i++;
		}
		
		printf("Whitelist size: %ld\n", whitelist.size());
		
		//then close the file
		whiteRead.close();
	}
	else
	{
		//open up log file
		ofstream sysLog("sys_log.txt", ios::app);
		
		//display messgaes
		printf("Unable to find whitelist file \"whitelist.txt\", please make sure the file is in the program directory.\n");
		getTime(timeString);
		sysLog << timeString << "Unable to find whitelist file \"whitelist.txt\", please make sure the file is in the program directory.\n\n";
		
		//close log file and exit the program
		sysLog.close();
		exit (EXIT_FAILURE);
	}
	return;	
}

//test the key against the whitelist
bool testKey(vector <int> &whitelist, int keyTry)
{
	uint8_t i = 0;

	//traverse the array to try and find the string
	for(i = 0; i < whitelist.size(); i++)
	{
		if(whitelist[i] == keyTry)
		{
		  return true;
		}
	}
	return false;
}

//Returns the current time as a character array
void getTime(char* timeString)
{
	time_t rawTime = time(NULL);
	struct tm * timeInfo = localtime(&rawTime);
	strcpy(timeString, asctime(timeInfo));
	strtok(timeString, "\n");
	
	return;
}

//writes to access log whethter passed or not
void accLog(bool pass, int keyTry, sockaddr_in &clientIP)
{
	char timeString[30];
	
	//open up log file
	ofstream accLog("acc_log.txt", ios::app);
	
	//get the current time
	getTime(timeString);
	
	//write the message to the file
	printf("%s Request from IP: %s For user: %d Pass(1)/Failed(0): %d\n", timeString, inet_ntoa(clientIP.sin_addr), keyTry, pass);
	accLog << timeString << " Request from IP: " << inet_ntoa(clientIP.sin_addr) << "For user: " << keyTry << "Pass(1)/Failed(0): " << pass << "\n";
	
	//close log file and exit the program
	accLog.close();
}
