#ifndef __AT_DEVICE_H__
#define __AT_DEVICE_H__

typedef struct
{
	int cmd_ex_type;
	void* cmd_ex_args;
}at_device_cmd_ex_args, *at_device_cmd_ex_args_t;	//��չ�����������

typedef enum
{
    AT_DEVICE_EVT_AT_CONN_OK,		//AT�豸���ӳɹ�
	AT_DEVICE_EVT_AT_CONN_FAIL,		//AT�豸����ʧ��
	AT_DEVICE_EVT_NET_REG_OK,		//����ע��ɹ�
	AT_DEVICE_EVT_NET_REG_FAIL,		//����ע��ʧ��
	AT_DEVICE_EVT_NET_REG_DENY,		//����ע�ᱻ�ܾ�(����ҵ�񱻽���)
	AT_DEVICE_EVT_NET_CONN_OK,		//�������ӳɹ�
	AT_DEVICE_EVT_NET_CONN_FAIL,	//��������ʧ��
	AT_DEVICE_EVT_IP_ADDRESS,		//IP��ַ
	AT_DEVICE_EVT_SIGNAL_STRENGTH,	//�ź�ǿ�Ȱٷֱ�
	AT_DEVICE_EVT_BASELOC,			//��վ��λ��Ϣ
	AT_DEVICE_EVT_GPS,				//GPS��λ��Ϣ
	AT_DEVICE_EVT_EXTENTION,		//������չ�¼�
	AT_DEVICE_EVT_ALL
}at_device_evt_t;

typedef enum
{
	AT_DEVICE_CMD_EXTENTION,		//��չ����
	AT_DEVICE_CMD_POWER,			//���Ƶ�Դ
	AT_DEVICE_CMD_RESET,			//���Ƹ�λ
	AT_DEVICE_CMD_INIT_NET,			//��ʼ����������
	AT_DEVICE_CMD_LOW_POWER,		//����͹���
	AT_DEVICE_CMD_SLEEP,			//��������
	AT_DEVICE_CMD_WAKEUP,			//����
	AT_DEVICE_CMD_IP,				//��ȡIP��ַ
	AT_DEVICE_CMD_SIGNAL,			//��ȡ�ź�ǿ�Ȱٷֱ�
	AT_DEVICE_CMD_BASELOC,			//��ȡ��վ��λ��Ϣ
	AT_DEVICE_CMD_GPS,				//��ȡGPS��λ��Ϣ
}at_device_cmd_t;

typedef void (*at_device_evt_cb_t)(at_device_evt_t event, void* args);
typedef int (*at_device_control_t)(at_device_cmd_t cmd, void* in_args, void* out_result);

void at_device_set_event_cb(at_device_evt_t event, at_device_evt_cb_t cb);
void at_device_set_control(at_device_control_t at_device_control);
void at_device_event_callback(at_device_evt_t event, void* args);
int at_device_control(at_device_cmd_t cmd, void* in_args, void* out_result);

#endif
