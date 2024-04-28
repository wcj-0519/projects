#pragma once
#include <map>
#include <string>
#include "TcpSocket.h"
#include "Message.pb.h"
#include "SecKeyShm.h"

using namespace std;
// 处理客户端请求
class ServerOP
{
public:
	enum KeyLen { Len16 = 16, Len24 = 24, Len32 = 32 };
	ServerOP(string json);
	// 启动服务器
	void startServer();
	// 线程工作函数 -> 推荐使用
	static void* working(void* arg);
	// 友元破坏了类的封装
	friend void* workHard(void* arg);
	string seckeyAgree(RequestMsg* msg);
	~ServerOP();
private:
	string getRandStr(int num);

private:
	string m_serverID;
	unsigned short m_port;
	SecKeyShm* m_shm;
	map<pthread_t, TcpSocket*> m_list;
};

void* workHard(void* arg);

