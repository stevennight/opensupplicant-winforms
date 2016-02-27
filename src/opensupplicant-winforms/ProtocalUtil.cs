using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace OpenSupplicant
{
    class ProtocalUtil
    {
        public const byte FIELD_ACTION = 0x00;	    // 操作
        public const byte FIELD_USER = 0x01;        // 帐户
        public const byte FIELD_PSWD = 0x02;        // 密码
        public const byte FIELD_SUCCESS = 0x03;     // 是否成功

        public const byte FIELD_UNKNOWN05 = 0x05;	// 未知，登录成功时返回
        public const byte FIELD_UNKNOWN06 = 0x06;	// 未知，登录成功时返回
        public const byte FIELD_MAC = 0x07;     	// MAC地址
        public const byte FIELD_SESSION = 0x08;     // 会话（注意：服务器返回的长度会少算2字节）
        public const byte FIELD_IP = 0x09;          // IP地址
        public const byte FIELD_SERVICE = 0x0a; 	// 认证服务
        public const byte FIELD_MESSAGE = 0x0b; 	// 服务器消息（注意：服务器返回的长度会少算2字节）
        public const byte FIELD_SERVER = 0x0c;	    // 认证服务器IP

        public const byte FIELD_DHCP = 0x0e;        // 是否DHCP

        public const byte FIELD_WEBSITE = 0x13;	    // 自助服务地址
        public const byte FIELD_SEQ = 0x14;     	// 请求序号

        public const byte FIELD_VERSION = 0x1f;	    // 客户端版本

        public const byte FIELD_UNKNOWN20 = 0x20;	// 未知，登录成功时返回

        public const byte FIELD_UNKNOWN23 = 0x23;	// 未知，登录成功时返回
        public const byte FIELD_REASON = 0x24;      // 下线原因

        public const byte FIELD_BLOCK2A = 0x2a; 	// 6个4字节数据块，心跳和注销时发送
        public const byte FIELD_BLOCK2B = 0x2b;
        public const byte FIELD_BLOCK2C = 0x2c;
        public const byte FIELD_BLOCK2D = 0x2d;
        public const byte FIELD_BLOCK2E = 0x2e;
        public const byte FIELD_BLOCK2F = 0x2f;

        public const byte FIELD_BLOCK30 = 0x30;	    // 2个未知用途4字节数据块，开放权限后返回
        public const byte FIELD_BLOCK31 = 0x31;

        public const byte FIELD_UNKOWN32 = 0x32;

        public const byte FIELD_BLOCK34 = 0x34; 	// 5个未知用途4字节数据块，登录成功时返回
        public const byte FIELD_BLOCK35 = 0x35;
        public const byte FIELD_BLOCK36 = 0x36;
        public const byte FIELD_BLOCK37 = 0x37;
        public const byte FIELD_BLOCK38 = 0x38;


        public const byte ACTION_LOGIN = 0x01;	        // 登录
        public const byte ACTION_LOGIN_RET = 0x02;
        public const byte ACTION_POLL = 0x03;	        // 心跳轮询
        public const byte ACTION_POLL_RET = 0x04;
        public const byte ACTION_LOGOUT = 0x05;         // 注销
        public const byte ACTION_LOGOUT_RET = 0x06;
        public const byte ACTION_SERVICE = 0x07;	    // 搜索认证服务
        public const byte ACTION_SERVICE_RET = 0x08;
        public const byte ACTION_DISCONNECT = 0x09;     // 被踢下线
        public const byte ACTION_CONFIRM = 0x0a;	    // 开放权限
        public const byte ACTION_CONFIRM_RET = 0x0b;
        public const byte ACTION_SERVER = 0X0c;  	    // 搜索认证服务器
        public const byte ACTION_SERVER_RET = 0x0d;


        public static byte[] BuildRequestBody(Dictionary<byte, byte[]> pars)
        {
            byte start = 2 + 16;
            byte length = start;
            byte action = pars[FIELD_ACTION][0];

            pars.Remove(FIELD_ACTION);
            
            // 计算报文总长度
            foreach (KeyValuePair<byte, byte[]> item in pars)
            {
                length += (byte)(item.Value.Length + 2);
            }

            // 报文
            byte[] ret = new byte[length];

            ret[0] = action;    // 报文类型
            ret[1] = length;    // 报文总长度

            foreach (KeyValuePair<byte, byte[]> item in pars)
            {
                ret[start] = item.Key;
                ret[start + 1] = (byte)(item.Value.Length + 2);
                for (byte i = 0; i < item.Value.Length; i++)
                {
                    ret[start + 2 + i] = item.Value[i];
                }
                start += ret[start + 1];
            }

            // 计算报文校验码并填充入报文
            byte[] hash = new MD5CryptoServiceProvider().ComputeHash(ret);
            for (byte i = 0; i < 16; i++)
            {
                ret[i + 2] = hash[i];
            }

            return ret;
        }

        public static Dictionary<byte, List<byte[]>> ParseResponseBody(byte[] buf)
        {
            //  DoS :数组溢出崩溃 2015/12/21
            if (buf.Length <= 16)
            {
                return null;
            }

            byte[] hash = new byte[16];
            for (byte i = 0; i < 16; i++)
            {
                hash[i] = buf[i + 2];
                buf[i + 2] = 0x00;
            }

            if (new MD5CryptoServiceProvider().ComputeHash(buf) == hash)
            {
                throw new ArgumentException("数据校验错误");
            }

            Dictionary<byte, List<byte[]>> ret = new Dictionary<byte, List<byte[]>>();

            //  返回消息长度过长超出byte范围(0-255)改用int。 16.02.28
            //  表示不是很明白怎么看。不过调试看到offset好像会达到279。
            //byte offset = 18;
            int offset = 18;
            if (buf[0] == ACTION_CONFIRM_RET) offset += 3;  // 服务器BUG

            ret.Add(FIELD_ACTION, new List<byte[]>());
            ret[FIELD_ACTION].Add(new byte[1] { buf[0] });

            while (offset < buf.Length)
            {
                byte fieldName = buf[offset];
                byte fieldLength = (byte)(buf[offset + 1] - 2);
                if (fieldName == FIELD_SESSION || fieldName == FIELD_MESSAGE) fieldLength += 2; // 服务器BUG

                byte[] fieldValue = new byte[fieldLength];
                //改用int 16.02.28
                //for (byte i = 0; i < fieldLength; i++)
                for (int i = 0; i < fieldLength; i++)
                {
                    fieldValue[i] = buf[offset + 2 + i];
                }

                if (!ret.ContainsKey(fieldName))
                {
                    ret.Add(fieldName, new List<byte[]>());
                }

                ret[fieldName].Add(fieldValue);

                //offset改用int 16.02.28
                //offset += (byte)(fieldLength + 2);
                offset += fieldLength + 2;
            }

            return ret;
        }
    }
}
