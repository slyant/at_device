#ifndef __AT_DEVICE_H__
#define __AT_DEVICE_H__

typedef enum
{
    AT_DEVICE_EVT_AT_CONN_OK,		//AT�豸���ӳɹ�
	AT_DEVICE_EVT_AT_CONN_FAIL,		//AT�豸����ʧ��
	AT_DEVICE_EVT_NET_REG_OK,		//��Ӫ������ע��ɹ�
	AT_DEVICE_EVT_NET_REG_FAIL,		//��Ӫ������ע��ʧ��
	AT_DEVICE_EVT_NET_REG_DENY,		//��Ӫ������ע�ᱻ�ܾ�(����ҵ�񱻽���)
	AT_DEVICE_EVT_NET_CONN_OK,		//��Ӫ���������ӳɹ�
	AT_DEVICE_EVT_NET_CONN_FAIL,	//��Ӫ����������ʧ��
	AT_DEVICE_EVT_SIGNAL_STRENGTH,	//�ź�ǿ�Ȱٷֱ�
	AT_DEVICE_EVT_IP_ADDRESS,		//IP��ַ
	AT_DEVICE_EVT_GSMLOC,			//��վ��λ��Ϣ
	AT_DEVICE_EVT_GPS,				//GPS��λ��Ϣ
	AT_DEVICE_EVT_EXTENTION,		//�����¼���չ
	AT_DEVICE_EVT_COUNT
}at_device_evt_t;

typedef void (*at_device_evt_cb_t)(at_device_evt_t event, void* args);

void at_device_set_event_cb(at_device_evt_t event, at_device_evt_cb_t cb);
void at_device_control(const char* cmd, void* args);

#endif
