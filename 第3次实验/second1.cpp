/*
* THIS FILE IS FOR IP FORWARD TEST
*/
#include "sysInclude.h"

// system support
extern void fwd_LocalRcv(char *pBuffer, int length);

extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);

extern void fwd_DiscardPkt(char *pBuffer, int type);

extern unsigned int getIpv4Address( );

// implemented by students
# include <vector>

struct table
{
    int dest;
    int nexthop;
};
vector<table> routerTable;

void stud_Route_Init()
{
    routerTable.clear();
	return;
}

void stud_route_add(stud_route_msg *proute)
{
    table t;
	//根据掩码长度和原IP地址更新新的IP地址
    t.dest = (ntohl(proute->dest))&(0xffffffff<<(32-htonl(proute->masklen)));
	//添加下一跳
    t.nexthop = ntohl(proute->nexthop);
    routerTable.push_back(t);
	return;
}


int stud_fwd_deal(char *pBuffer, int length)
{
    int version = pBuffer[0] >>4;
    int ihl = pBuffer[0]&0xf;
    int ttl = (int)pBuffer[8];
    int checksum = ntohs(*(unsigned short*)(pBuffer+10));
    int destIP = ntohl(*(unsigned int*)(pBuffer+16));

    //如果是本机就提交给上层
    if(destIP == getIpv4Address()){
        fwd_LocalRcv(pBuffer,length);
        return 0;
    }
    // 如果生存时间错误就抛出错误
    if(ttl <= 0)
    {
        fwd_DiscardPkt(pBuffer,STUD_FORWARD_TEST_TTLERROR);
        return 1;
    }
    vector<table>::iterator ite;
	// 在路由表中查找
    for(ite = routerTable.begin();ite!=routerTable.end();ite++){
        if(ite->dest == destIP){
            char* buffer = new char[length];
            memcpy(buffer,pBuffer,length);
            buffer[8]--;              //ttl减1

		//重新计算checksum
            unsigned short checksum = 0;
            unsigned short temp;
            unsigned short f = 0;
            int i =0;
            for(i = 0;i < ihl*2;i++){
                if(i!=5){
                    temp = (buffer[2*i]<<8) + (buffer[2*i+1]);
                    if((unsigned short)(temp+checksum)<checksum){
                        f = 1;
                    }else{
                        f = 0;
                    }
                    checksum = checksum +f +temp;
                }
            }
            checksum =htons( ~checksum);
			
			//更新checksum
            memcpy(buffer+10,&checksum,sizeof(unsigned short));
			//实现转发
            fwd_SendtoLower(buffer,length,ite->nexthop);
            return 0;
        }

    }
	//如果转发地址不在路由表中
      fwd_DiscardPkt(pBuffer,STUD_FORWARD_TEST_NOROUTE);
	return 1;
}