/**
 * Author:    PETR KNETL
 * Created:   3.4.2018
 *
 * Project: School project ě to IPK class, basic DNS lookup tool
 **/
 #include <stdio.h>
 #include <stdlib.h>
 #include <getopt.h>
 #include <ctype.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <unistd.h>
 #include <string.h>
 #include <sys/time.h>
 #include <stdbool.h>

 // types of DNS questions
 #define DNS_QTYPE_A		1
 #define DNS_QTYPE_NS		2
 #define DNS_QTYPE_PTR		12
 #define DNS_QTYPE_AAAA		28
 #define DNS_QTYPE_CNAME		5

//***********************************************************************************
// struktury prevzaty z https://www.binarytides.com/dns-query-code-in-c-with-winsock/
//***********************************************************************************
 struct DNS_HEADER{
  unsigned short id; // identification number
  unsigned char rd :1; // recursion desired
  unsigned char tc :1; // truncated message
  unsigned char aa :1; // authoritive answer
  unsigned char opcode :4; // purpose of message
  unsigned char qr :1; // query/response flag
  unsigned char rcode :4; // response code
  unsigned char cd :1; // checking disabled
  unsigned char ad :1; // authenticated data
  unsigned char z :1; // its z! reserved
  unsigned char ra :1; // recursion available
  unsigned short q_count; // number of question entries
  unsigned short ans_count; // number of answer entries
  unsigned short auth_count; // number of authority entries
  unsigned short add_count; // number of resource entries
};

struct QUESTION{
  unsigned short qtype;
  unsigned short qclass;
};

#pragma pack(push, 1)
struct R_DATA{
  unsigned short type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD{
  unsigned char *name;
  struct R_DATA *resource;
  unsigned char *rdata;
};

  //Structure of a Query
typedef struct{
  unsigned char *name;
  struct QUESTION *ques;
} QUERY;



//global variables
unsigned char buf[65536], *qname, *reader;
struct DNS_HEADER *header = NULL;
struct QUESTION *qinfo = NULL;
struct RES_RECORD answers[20],authoritative_servers[20],add_info[20];
char hostname[256];
uint16_t type;

void DisplayHelp(){
  printf("HELP pro skript ipk-lookup:\n\n");
  printf("INFO : Program pro zobrazeni DNS cesty k vzdalenemu serveru\n\n");
  printf("POVOLENE PARAMETRY:    s (server) - povinný parametr, DNS server (IPv4 dns_address), na který se budou odesílat dotazy.\n");
  printf("                       T (timeout) - volitelný parametr, timeout (v sekundách) pro dotaz, výchozí hodnota 5 sekund\n");
  printf("                       t (type) - volitelný parametr, typ dotazovaného záznamu: A (výchozí), AAAA, NS, PTR, CNAME\n");
  printf("                       i (iterative) - volitelný parametr, vynucení iterativního způsobu rezoluce\n");
  printf("                       n (name) - povinný parametr (MUSÍ BÝT POSLEDNÍ UVEDENÝ), překládané doménové jméno, v případě\n");
  printf("                                  parametru -t PTR program na vstupu naopak očekává IPv4 nebo IPv6 adresu\n\n");
  exit(0);
 }


void ConvertDNS(unsigned char* header, char* host){
    int delimer=0;
    int i = 0;

    strcat((char*)host,".");

    while(i<(int)strlen((char*)host)){
        if(host[i]=='.'){
            *header++=i-delimer;
            for(;delimer<i;delimer++){
                *header++=host[delimer];
            }
            delimer++; //or delimer=i+1;
        }
        i++;
    }
    *header++='\0';
 }

//transfer string to lowercase
char *strlwr( char *str){
   char *p = ( char *)str;

  while (*p) {
   *p = tolower(( char)*p);
    p++;
  }

    return  str;
}

//set recursive standart query
void SetQuery(){
    memset(buf, 0, 65536);
    header=(struct DNS_HEADER*)&buf;

    header=(struct DNS_HEADER*)&buf;

    header->id = (unsigned short)htons(getpid());
    header->qr = 0; //This is a query
    header->opcode = 0; //This is a standard query
    header->aa = 0; //Not Authoritative
    header->tc = 0; //This message is not truncated

    header->rd = 1;

    header->ra = 0;
    header->z = 0;
    header->ad = 0;
    header->cd = 0;
    header->rcode = 0;
    header->q_count = htons(1);
    header->ans_count = 0;
    header->auth_count = 0;
    header->add_count = 0;

    //point on end of header
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
    ConvertDNS(qname, hostname);

    //point on end of qname
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*) qname) + 1)];

    qinfo->qtype = htons(type); // request for specific type
    qinfo->qclass = htons(1); //set class as internet
}

unsigned char* ConvertNameFormat(unsigned char* reader,unsigned char* buffer,int* count);

void ReadResponse(){
  int stop = 0;
  for(int i=0;i<ntohs(header->ans_count);i++){
      answers[i].name= ConvertNameFormat(reader,buf,&stop);
      reader = reader + stop;

      answers[i].resource = (struct R_DATA*)(reader);
      reader = reader + sizeof(struct R_DATA) ;

      if(ntohs(answers[i].resource->type) == DNS_QTYPE_A){ //if its an ipv4 address
          answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
          for(int j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
          {
              answers[i].rdata[j]=reader[j];
          }

          answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

          reader = reader + ntohs(answers[i].resource->data_len);
        }
      else if(ntohs(answers[i].resource->type) == DNS_QTYPE_AAAA){ //it is IPv6 address
          answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
          for(int j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
          {
            answers[i].rdata[j]=reader[j];
          }

        answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

        reader = reader + ntohs(answers[i].resource->data_len);
      }
      else{ // other types

          answers[i].rdata = ConvertNameFormat(reader,buf,&stop);
          reader = reader + stop;
      }
}// read answers loop


    //read authorities
    for(int i=0;i<ntohs(header->auth_count);i++){
        authoritative_servers[i].name= ConvertNameFormat(reader,buf,&stop);
        reader+=stop;

        authoritative_servers[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);

        authoritative_servers[i].rdata= ConvertNameFormat(reader,buf,&stop);
        reader+=stop;
    }

    //read additional
    for(int i=0;i<ntohs(header->add_count);i++){
        add_info[i].name= ConvertNameFormat(reader,buf,&stop);
        reader+=stop;

        add_info[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);

        if(ntohs(add_info[i].resource->type)==1)
        {
            add_info[i].rdata = (unsigned char*)malloc(ntohs(add_info[i].resource->data_len));
            for(int j=0;j<ntohs(add_info[i].resource->data_len);j++)
            add_info[i].rdata[j]=reader[j];

            add_info[i].rdata[ntohs(add_info[i].resource->data_len)]='\0';
            reader+=ntohs(add_info[i].resource->data_len);
        }
        else
        {
            add_info[i].rdata= ConvertNameFormat(reader,buf,&stop);
            reader+=stop;
        }
    }
}

 unsigned char* ConvertNameFormat(unsigned char* reader,unsigned char* buffer,int* count){
     unsigned char *string;
     unsigned int p=0,move=0,offset;
     int i , j;
     *count = 1;
     string = (unsigned char*)malloc(256);
     string[0]='\0';
     while(*reader!=0){
         if(*reader>=192)
         {
             offset = (*reader)*256 + *(reader+1) - 49152;
             reader = buffer + offset - 1;
             move = 1; //set help variable
         }
         else
         {
             string[p++]= *reader;
         }

         reader=reader+1;

         if(move==0) *count = *count + 1;
     }
     string[p]='\0'; //string complete

     if(move==1){
         *count = *count + 1; //number of steps we actually moved forward in the packet
     }

     for(i=0;i<(int)strlen((const char*)string);i++){
         p=string[i];
         for(j=0;j<(int)p;j++)
         {
             string[i]=string[i+1];
             i=i+1;
         }
         string[i]='.';
     }

     string[i-1]='\0'; //remove dot
     return string;
 }



 int main(int argc, char* argv[]){

 // pomocne promenne pro getopt()
  int par;
  int long_index =0;
  int hflag, sflag, Tflag, tflag, iflag;
  hflag = sflag = Tflag = tflag = iflag = 0;
  char dns_name[256];
  char t[256];
  char T[256];
  strcpy(t, "A");
  strcpy(T, "5");


  static struct option long_options[] = {
         {"help",      no_argument,       0,  'h' },
         {"server",    required_argument, 0,  's' },
         {"timeout",   required_argument, 0,  'T' },
         {"type",      required_argument, 0,  't' },
         {"iterative", no_argument,       0,  'i' },
         {0,           0,                 0,   0  }
     };


  while ((par = getopt_long(argc, argv, "hs:T:t:i", long_options, &long_index)) != -1) { //zpracovani parametru
     switch (par){

       case 'h':
         hflag = 1;
         break;

       case 's':
         sflag = 1;
         strncpy(dns_name, optarg, sizeof(dns_name));
         break;

       case 'T':
         Tflag = 1;
         strncpy(T, optarg, sizeof(T));
         if (strcmp(T, "0") == 0){
           printf("ERROR: Unable to se timeout custom timeout value, keeping default value (timeout = 5 s)\n");
            strcpy(T, "5");
         }
         break;

       case 't':
         tflag = 1;
         strncpy(t, optarg, sizeof(t));
         break;

       case 'i':
         iflag = 1;
         break;


       case '?':
         if (optopt == 's' || optopt == 'T' || optopt == 't' )
           fprintf (stderr, "Option -%c requires an argument.\n", optopt);
         else if (isprint(optopt)){
           fprintf (stderr, "Unknown option `-%c'.\n", optopt);
         }
         else
           fprintf (stderr,
                    "Unknown option character `\\x%x'.\n",
                    optopt);
         exit(2);
       default:
         abort ();
       }

  }

  if(hflag){
    DisplayHelp();
  }

  if (sflag == 0){
    exit(2); // missing -s parameter
  }


  strncpy(hostname, argv[argc-1], sizeof(hostname));

   if(strcmp(hostname, "-i") == 0 || strcmp(hostname, dns_name) == 0 || strcmp(hostname, t) == 0 || strcmp(hostname, T) == 0|| strcmp(hostname, argv[0]) == 0){
     exit(2); // mising 'name' parameter
   }

  struct timeval timeout;
  timeout.tv_sec = atoi(T);
  timeout.tv_usec = 0;

  if (tflag){
    if (strcmp(t, "A") == 0)
      type = DNS_QTYPE_A;

    else if (strcmp(t, "NS") == 0)
      type = DNS_QTYPE_NS;

    else if (strcmp(t, "AAAA") == 0)
      type = DNS_QTYPE_AAAA;

    else if (strcmp(t, "CNAME") == 0)
      type = DNS_QTYPE_CNAME;

    else if (strcmp(t, "PTR") == 0){
      type = DNS_QTYPE_PTR;
    }
    else{
      exit(2); // wrong type parameter
    }
  }
  else
    type = DNS_QTYPE_A;


  int Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //NAstaveni ssocketu pro UDP protokol

  if (setsockopt (Socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
      exit(1); //Error: setsockopt failed
  }

  //nastaveni adresy dotazovaneho DNS serveru
  struct sockaddr_in dns_address;
  dns_address.sin_family=AF_INET;
  dns_address.sin_port=htons(53);
  dns_address.sin_addr.s_addr=inet_addr(dns_name);





  SetQuery();
  if(iflag == 1)
    header->rd = 0; // iterative lookup option


  if( sendto(Socket,(char*)buf,sizeof(header) + sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION) ,0,(struct sockaddr*)&dns_address,sizeof(dns_address)) < 0){
    exit(1); //ERROR: unable to send query
  }

  int i = sizeof(dns_address);
  memset(buf, 0, 65536);


  if(recvfrom(Socket,(char*)buf,65536,0,(struct sockaddr*)&dns_address,(socklen_t*)&i) < 0){
    exit(1); //ERROR: Unable to get response from DNS server
  }
  header=(struct DNS_HEADER*)buf;


  //move ahead of the dns header and the query field
  reader= &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION) ]; //correct


  ReadResponse();
  if (header->rcode != 0){
    exit(1); //ERROR on the server side
  }


    if(iflag == 0){ // iterative is disabled ( we will make recursive query)
        if( ntohs(header->ans_count) == 0){//ERROR: DNS server doesn't have Answer
          exit(1); //ERROR: DNS server doesn't have Answer
        }
        bool found = false;
        for(i=0;i<ntohs(header->ans_count);i++){

          if (ntohs(answers[i].resource->type) == type){
            found = true;
          }
          printf("%s. IN ",answers[i].name);

          if(ntohs(answers[i].resource->type) == DNS_QTYPE_A) //IPv4 address
          {
              struct sockaddr_in ipv4;
              long *p;
              p= (long*)answers[i].rdata;
              ipv4.sin_addr.s_addr=(*p); //working without ntohl
              printf("A %s", inet_ntoa(ipv4.sin_addr));
            }
          if(ntohs(answers[i].resource->type) == DNS_QTYPE_AAAA){ //IPv4 address

            char str[1024];
            struct sockaddr_in6 ipv6;
            memcpy(&ipv6.sin6_addr.s6_addr, answers[i].rdata, 16);
            printf("AAAA %s", inet_ntop(AF_INET6, &(ipv6.sin6_addr), str, 1024));
          }

          if(ntohs(answers[i].resource->type)== DNS_QTYPE_CNAME){ //CNAME

              printf("CNAME %s.",answers[i].rdata);
          }

          printf("\n");
        }

        if (found){ //we found searched type
          exit(0);
        }
        else{ //we haven't found
          exit(1);//error
        }


    }
    else{ // iterative query
      bool first = true;

      while(ntohs(header->add_count) != 0){ //while there is additional info

        if(ntohs(header->aa) == 1){ // if asnwer is authoritative

          bool found = false;
          for(i=0;i<ntohs(header->ans_count);i++){

            if (ntohs(answers[i].resource->type) == type){
              found = true;
            }
            printf("%s. IN ",answers[i].name);

            if(ntohs(answers[i].resource->type) == DNS_QTYPE_A) //IPv4 address
            {
                struct sockaddr_in ipv4;
                long *p;
                p= (long*)answers[i].rdata;
                ipv4.sin_addr.s_addr=(*p); //working without ntohl
                printf("A %s", inet_ntoa(ipv4.sin_addr));
              }
            if(ntohs(answers[i].resource->type) == DNS_QTYPE_AAAA){ //IPv4 address

              char str[1024];
              struct sockaddr_in6 ipv6;
              memcpy(&ipv6.sin6_addr.s6_addr, answers[i].rdata, 16);
              printf("AAAA %s", inet_ntop(AF_INET6, &(ipv6.sin6_addr), str, 1024));
            }

            if(ntohs(answers[i].resource->type)== DNS_QTYPE_CNAME){ //CNAME
                printf("CNAME %s.",answers[i].rdata);
            }

            if (found){ //we found searched type
              exit(0);
            }
            else{ //we haven't found
              exit(1);//error
            }
          }
        }
        else{ //create next querry
          struct RES_RECORD chosen_addit;
          char authoritative_server[256] = "";
          for(i=0;i<ntohs(header->add_count);i++){
            if(ntohs(add_info[i].resource->type) == DNS_QTYPE_A){
              chosen_addit = add_info[i];
              strcpy(authoritative_server, strlwr((char*) chosen_addit.name));
              strcat(authoritative_server, ".");
            }
          }
          if (strcmp(authoritative_server, "") == 0){
            exit(1); // ERROR: Cannot find authoritative server with informations about searched adress
          }

          struct sockaddr_in ipv4;
          long *p;
          p= (long*)chosen_addit.rdata;
          ipv4.sin_addr.s_addr=(*p); //working without ntohl
          const char delim[2] = ".";
          char domain_name[256];
          char temp_string[256];
          strcpy(temp_string,authoritative_server);
          char *token;

          /* get the first token */
          token = strtok(temp_string, delim);

          /* walk through other tokens */
          while( token != NULL ) {
            strcpy(domain_name, token);
            token = strtok(NULL, delim);
          }

          if(first){
            strcpy(domain_name, ".");
          }


          printf(" %s IN NS %s\n",domain_name, authoritative_server);
          printf(" %s IN A %s\n",authoritative_server, inet_ntoa(ipv4.sin_addr));
          first = false;


          SetQuery();
          header->rd = 0; // iterative lookup option
          char new_dns_server[256];
          strcpy(new_dns_server, inet_ntoa(ipv4.sin_addr));
          dns_address.sin_addr.s_addr= inet_addr(new_dns_server);

          //sending query
          if( sendto(Socket,(char*)buf,sizeof(header) + sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION) ,0,(struct sockaddr*)&dns_address,sizeof(dns_address)) < 0){
            exit(1); //ERROR: unable to send query
          }

          //fetching query
          if(recvfrom(Socket,(char*)buf,65536,0,(struct sockaddr*)&dns_address,(socklen_t*)&i) < 0){
            exit(1); //ERROR: Unable to get response from DNS server
          }

          header=(struct DNS_HEADER*)buf;


          //point address of buffer behind query
          reader= &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION) ]; //correct



          ReadResponse();
          if (header->rcode != 0){ //error on the server side
            exit(1);
          }
        }//end of setting new query

      }// end of iterative lookup cycle
      if(ntohs(header->aa) == 1){ // if asnwer is authoritative

        bool found = false;
        for(i=0;i<ntohs(header->ans_count);i++){

          if (ntohs(answers[i].resource->type) == type){
            found = true;
          }
          printf("%s. IN ",answers[i].name);

          if(ntohs(answers[i].resource->type) == DNS_QTYPE_A) //IPv4 address
          {
              struct sockaddr_in ipv4;
              long *p;
              p= (long*)answers[i].rdata;
              ipv4.sin_addr.s_addr=(*p); //working without ntohl
              printf("A %s", inet_ntoa(ipv4.sin_addr));
            }
          if(ntohs(answers[i].resource->type) == DNS_QTYPE_AAAA){ //IPv4 address

            char str[1024];
            struct sockaddr_in6 ipv6;
            memcpy(&ipv6.sin6_addr.s6_addr, answers[i].rdata, 16);
            printf("AAAA %s", inet_ntop(AF_INET6, &(ipv6.sin6_addr), str, 1024));
          }

          if(ntohs(answers[i].resource->type)== DNS_QTYPE_CNAME){ //CNAME
              printf("CNAME %s.",answers[i].rdata);
          }

          if (found){ //we found searched type
            exit(0);
          }
          else{ //we haven't found
            exit(1);//error
          }
        }
      }

      exit(1);// ERROR: Unable to find other authoritative server

    }//end of iterative query



}//end of main
