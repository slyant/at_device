#ifndef __AT_SOCKET_AIR800_H__
#define __AT_SOCKET_AIR800_H__

typedef enum
{
	AIR800_CMD_TTS_SET,
	AIR800_CMD_TTS_PLAY,
	AIR800_CMD_TTS_STOP,
}air800_cmd_t;

typedef struct
{
	int volume;		//��������(0-100)
	int mode;		//���ֲ���ģʽ(0-3)
	int pitch;		//��������(1-100)
	int speed;		//�����ٶ�(1-100)
	int channel;	//����ͨ��:(0)main channel;(1)aux channel
}air800_args_tts_set, *air800_args_tts_set_t;

typedef struct
{
	int mode;		//TTS����ģʽ:
								//(0)ֹͣ����TTS;
								//(1)����TTS��textʹ��UCS2����;
								//(2)����TTS��textʹ��ASCII(Ӣ��)��GBK����(����)
	char* text;		//TTS�ı�,��󳤶�479���ַ�
}air800_args_tts_play, *air800_args_tts_play_t;

#endif
