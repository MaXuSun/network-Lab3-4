/*
* THIS FILE IS FOR IP TEST
*/
// system support
#include "sysInclude.h"

extern void ip_DiscardPkt(char* pBuffer,int type);

extern void ip_SendtoLower(char*pBuffer,int length);

extern void ip_SendtoUp(char *pBuffer,int length);

extern unsigned int getIpv4Address();

// implemented by students


int stud_ip_recv(char* pBuffer,unsigned short length)
{

    int version = pBuffer[0] >>4;
    int hl = pBuffer[0]&0xf;
    int ttl = (int)pBuffer[8];
    unsigned short headerChecksum = ntohs(*(unsigned short*)(pBuffer+10));
    int dst = ntohl(*(unsigned int*)(pBuffer+16));

    if(version!=4){
       ip_DiscardPkt(pBuffer,STUD_IP_TEST_VERSION_ERROR);
       return 1;
    }
    if(hl < 5){
       ip_DiscardPkt(pBuffer,STUD_IP_TEST_HEADLEN_ERROR);
       return 1;
    }
    if(ttl <= 0 ){
       ip_DiscardPkt(pBuffer,STUD_IP_TEST_TTL_ERROR);
       return 1;
    }
    if(dst!=getIpv4Address()&&dst!=0xffffff){
       ip_DiscardPkt(pBuffer,STUD_IP_TEST_DESTINATION_ERROR);
       return 1;
    }
    unsigned short checksum = 0;
    unsigned short temp;
    unsigned short f = 0;
    int i = 1;
    for(i = 0;i<hl*2;i++){
       if(i!=5){
           temp = ((pBuffer[2*i])<<8) + (pBuffer[2*i+1]);
           if((unsigned short)(temp+checksum) < checksum){
               f = 1;
           }else{
               f = 0;
           }
           checksum = checksum+f+temp;
       }
    }
    checksum = ~checksum;
    if(checksum != headerChecksum){
       ip_DiscardPkt(pBuffer,STUD_IP_TEST_CHECKSUM_ERROR);
       return 1;
    }

    ip_SendtoUp(pBuffer,length);
    return 0;

   }
void printIP(unsigned char* a)
{
    int i = 0;
    for(i = 0;i < 20;i++){
        printf("%0x ",a[i]);
        if(i%4 == 3){
            printf("\n");
        }
    }
}

unsigned short caculate_checksum(char* pData,unsigned short allLen)
{
    unsigned short checksum= 0;
    unsigned short temp = 0;
    unsigned short i =0;
    unsigned short eight = 0xff00;
    unsigned short four = 0x00ff;
    unsigned short f = 0;
    char i_ip_1 = 0;
    char i_ip_2 = 0;

    for(i = 0;i < allLen;i+=2)
    {
        i_ip_1 = *(pData+i);
        i_ip_2 = *(pData+i+1);
        temp = ((i_ip_1&four)<<8) + (four&i_ip_2);
        if((unsigned short)(temp+checksum) < checksum){
            f = 1;
        }else{
            f = 0;
        }

        checksum = checksum+temp+f;

        //printf("i:%u  ,checksum:%0x\n",i,checksum);
    }

    checksum =~checksum;
    printf("checksum:%0x\n",checksum);
    return checksum;
}

int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
				   unsigned int dstAddr,byte protocol,byte ttl)
{
    unsigned char ip[20];
    unsigned char m = 0xff;
    unsigned char ver_ihl = 0x45;
    unsigned char tos = 0x00;
    unsigned char iplen = 20;
    unsigned short allLen = htons(len+iplen);
    unsigned short identification = 0x0000;
    unsigned short fragment = 0x0000;
    unsigned char TTL = (unsigned char)ttl;
    unsigned char Protocol = (unsigned char)protocol;
    unsigned int toSrcAddr = htonl(srcAddr);
    unsigned int todstAddr = htonl(dstAddr);
    unsigned short checksum = 0;
    char* pData = (char*)malloc((allLen)*sizeof(char));
    memcpy(pData+20,pBuffer,len);
    free(pBuffer);


    printf("length :%u\n",len);
    printf("srcAddr:%0x\n",srcAddr);
    printf("dstAddr:%0x\n",dstAddr);
    printf("protocol:%0x\n",protocol);
    printf("ttl     :%0x\n\n",ttl);

    int i = 0;
    //------------------------------第一行数据----------------//
    ip[0] = ver_ihl;
    ip[1] = tos;
    ip[2] = allLen&0x00ff;
    ip[3] = ((allLen>>8)&0x00ff);
    //------------------------------第二行数据-----------------//
    for(i = 4;i < 8;i++){
        ip[i] = 0x00;
    }
    //------------------------------第三行数据-----------------//
    ip[8] = ttl;
    ip[9] = Protocol;
    ip[10] = 0;
    ip[11] = 0;
    //-----------------------------第四行数据------------------//
    for(i = 12;i<16;i++){
        ip[i] = (toSrcAddr>>((i-12)*8))&0xff;
    }
    //-----------------------------第五行数据------------------//
    for(i = 16;i<20;i++){
        ip[i] = (todstAddr>>((i-16)*8))&0xff;
    }
    //----------------------------将数据封装到ip报文头中------//
    for(i=0;i<20;i++)
    {
        *(pData+i) = ip[i]&m;
    }

    checksum = caculate_checksum(pData,20);

    *(pData+10) = (unsigned char)((checksum>>8)&0xff);
    *(pData+11) = (unsigned char)(checksum&0xff);

    for(i = 0;i < 37;i++){
	printf("%0x ",(unsigned char)(*(pData+i)));
	if(i%4 == 3){
            printf("\n");
        }
    }

    pBuffer = pData;
    ip_SendtoLower(pBuffer,iplen+len);
    return 0;
}
