/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-10-27     slyant	first version
 */
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
	int volume;		//播放音量(0-100)
	int mode;		//数字播放模式(0-3)
	int pitch;		//播放音高(1-100)
	int speed;		//播放速度(1-100)
	int channel;	//播放通道:(0)main channel;(1)aux channel
}air800_args_tts_set, *air800_args_tts_set_t;

typedef struct
{
	int mode;		//TTS工作模式:
								//(0)停止播放TTS;
								//(1)播放TTS，text使用UCS2编码;
								//(2)播放TTS，text使用ASCII(英文)或GBK编码(中文)
	char* text;		//TTS文本,最大长度479个字符
}air800_args_tts_play, *air800_args_tts_play_t;

#endif
