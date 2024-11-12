#include "secure_qgc.h"
#include <QtCore/QSettings>
#include "mc.h"


void mesl_qgc_encrypt(const QByteArray& data, QByteArray& Edata){
    Edata.resize(0);
    if (static_cast<uint8_t>(data[0]) == 254) {
        Edata.append(data);
    }

    else if (static_cast<uint8_t>(data[0]) == 253) {
        uint8_t data_buf[280] {};
        uint8_t _Ebuf[256]{};
        int _Ebuf_c{ 0 };
        uint8_t _Bck[2]{};

        for(int position = 0; position<data.size(); position++){
            data_buf[position]=data[position];
        }
        memcpy(&_Bck[0],&data_buf[data_buf[1]+10],2);
        Encrypt_AES128(0,&data_buf[10],(int)data_buf[1],&_Ebuf[0],&_Ebuf_c);
        for(int header = 0; header < 10; header ++){
            Edata.append(data_buf[header]);
        }
        for(int payload = 0; payload<_Ebuf_c; payload++){
            Edata.append(_Ebuf[payload]);
        }
        for(int ck = 0;  ck<2; ck++){
            Edata.append(_Bck[ck]);
        }
        qCritical()<<"Send Encrypted Packet";
    }
}


void mesl_qgc_decrypt(QByteArray& b,QByteArray& packet_buf){
    int len_gap=0;
    int e_length = 0;

    uint8_t _Dbuf[256]{};
    int _Dbuf_c{ 0 };

    QByteArray header_buf;
    QByteArray payload_buf;
    QByteArray ck_buf;

    QByteArray temp_buf;

    QByteArray stream_buf;

    header_buf.resize(10);
    ck_buf.resize(2);

    int cipher_flag=1;

    packet_buf.append(b);

    while(cipher_flag==1){

        if(packet_buf.size()!=0){


            if(static_cast<uint8_t>(packet_buf[0])==253){

                if(packet_buf.size()>=7){

                    if(static_cast<uint8_t>(packet_buf[6])==68){
                        if(static_cast<uint8_t>(packet_buf[1]+12)<=packet_buf.size()){
                            temp_buf.resize(static_cast<uint8_t>(packet_buf[1])+12);
                            for(int position=0; position < static_cast<uint8_t>(packet_buf[1])+12; position++){
                                temp_buf[position]=packet_buf[position];
                            }
                            stream_buf.append(temp_buf);
                            packet_buf.remove(0,static_cast<uint8_t>(packet_buf[1])+12);
                        }
                        else{
                            cipher_flag=0;
                        }
                    }

                    else{
                        if ((static_cast<uint8_t>(packet_buf[1])) % 16 == 0)
                        {
                            e_length = (static_cast<uint8_t>(packet_buf[1]));
                        }
                        else
                        {
                            e_length = (((static_cast<uint8_t>(packet_buf[1])) / 16) + 1) * 16;
                        }

                        len_gap=e_length-(int)(static_cast<uint8_t>(packet_buf[1]));


                        if(e_length+12<=packet_buf.size()){

                            for(int position=0; position<10; position++){
                                header_buf[position]=packet_buf[position];
                            }


                            payload_buf.resize(static_cast<uint8_t>(packet_buf[1]));
                            Decrypt_AES128(0, (uint8_t*)&packet_buf[10], e_length, &_Dbuf[0], &_Dbuf_c);
                            qCritical()<<"Receive Encrypted Packet";
                            for(int position=0; position<static_cast<uint8_t>(packet_buf[1]); position++){
                                payload_buf[position]=_Dbuf[position];
                            }



                            for(int position=0; position<2; position++){
                                ck_buf[position]=packet_buf[position+e_length+10];
                            }



                            stream_buf.append(header_buf);
                            stream_buf.append(payload_buf);
                            stream_buf.append(ck_buf);

                            packet_buf.remove(0,12+e_length);

                        }
                        else if(e_length+12>packet_buf.size()){
                            cipher_flag=0;
                        }

                    }

                }

                else{
                    cipher_flag=0;
                }

            }


            else if(static_cast<uint8_t>(packet_buf[0])==254){
                if(packet_buf.size()!=1){
                    if(static_cast<uint8_t>(packet_buf[1])+8<=packet_buf.size()){
                        temp_buf.resize(static_cast<uint8_t>(packet_buf[1])+8);
                        for(int position=0; position < static_cast<uint8_t>(packet_buf[1])+8; position++){
                            temp_buf[position]=packet_buf[position];
                        }
                        stream_buf.append(temp_buf);
                        packet_buf.remove(0,8+static_cast<uint8_t>(packet_buf[1]));
                        qCritical()<<"plain packet";
                    }
                    else if(static_cast<uint8_t>(packet_buf[1])+8>packet_buf.size()){
                        cipher_flag=0;
                    }

                }
                else{
                    cipher_flag=0;
                }
            }

            else{
                //qCritical()<<"ERROR_DECRYPTION";
                packet_buf.remove(0,1);
            }


        }
        else{
            cipher_flag=0;
        }

    }

    b.remove(0,b.size());
    b.append(stream_buf);
}


void mesl_qgc_integrity_gen(const QByteArray& data, QByteArray& Edata) {
    Edata.resize(0);

    if (static_cast<uint8_t>(data[0]) == 254) {
        Edata.append(data);
    }
    else if (static_cast<uint8_t>(data[0]) == 253) {
        uint8_t data_buf[280] {};

        for (int position = 0; position < data.size(); position++) {
            data_buf[position] = data[position];
        }

        int _buf_len = static_cast<uint8_t>(data[1]) + 12;

        extern uint8_t AES_key[1][16];
        SHA256_CTX s_ctx;

        uint8_t s_hash[32];
        HMAC_Init(&s_ctx, AES_key[0]);
        HMAC_Update(&s_ctx, &data_buf[0], static_cast<uint8_t>(data[1]) + 12);
        HMAC_Final(&s_ctx, s_hash);

        for (int position = 0; position < _buf_len; position++) {
            Edata.append(data_buf[position]);
        }

        for (int position = 0; position < 13; position++) {
            Edata.append(s_hash[position]);
        }

        qCritical() << "SEND__________________SUCCESS";
    }
}


void mesl_qgc_integrity_check(QByteArray& b, QByteArray& packet_buf) {
    uint8_t _Dbuf[256]{};
    int _Dbuf_c{ 0 };

    uint8_t sig_buf[13]{}; // 크기 지정 필요

    QByteArray temp_buf;
    QByteArray stream_buf;

    int cipher_flag = 1;

    packet_buf.append(b);

    while (cipher_flag == 1) {
        if (packet_buf.size() != 0) {
            if (static_cast<uint8_t>(packet_buf[0]) == 253) {
                if (packet_buf.size() >= 7) {
                    if (static_cast<uint8_t>(packet_buf[6]) == 68) {
                        if (static_cast<uint8_t>(packet_buf[1]) + 12 <= packet_buf.size()) {
                            temp_buf.resize(static_cast<uint8_t>(packet_buf[1]) + 12);
                            for (int position = 0; position < static_cast<uint8_t>(packet_buf[1]) + 12; position++) {
                                temp_buf[position] = packet_buf[position];
                            }
                            stream_buf.append(temp_buf);
                            packet_buf.remove(0, static_cast<uint8_t>(packet_buf[1]) + 12);
                        } else {
                            cipher_flag = 0;
                        }
                    } else {
                        if (static_cast<uint8_t>(packet_buf[1]) + 12 + 13 <= packet_buf.size()) {
                            temp_buf.resize(static_cast<uint8_t>(packet_buf[1]) + 12);
                            for (int position = 0; position < static_cast<uint8_t>(packet_buf[1]) + 12; position++) {
                                temp_buf[position] = packet_buf[position];
                            }

                            for (int position = 0; position < 13; position++) {
                                sig_buf[position] = packet_buf[position + static_cast<uint8_t>(packet_buf[1]) + 12];
                            }

                            extern uint8_t AES_key[1][16];

                            SHA256_CTX v_ctx;
                            uint8_t v_hash[32];

                            HMAC_Init(&v_ctx, AES_key[0]);
                            HMAC_Update(&v_ctx, reinterpret_cast<uint8_t*>(&packet_buf[0]), static_cast<uint8_t>(packet_buf[1]) + 12);
                            HMAC_Final(&v_ctx, v_hash);

                            if (memcmp(&sig_buf[0], &v_hash[0], 13) == 0) {
                                packet_buf.remove(0, static_cast<uint8_t>(packet_buf[1]) + 12 + 13);
                                stream_buf.append(temp_buf);
                                qCritical() << "Integrity Check Success";
                            } else {
                                packet_buf.remove(0, 1);
                                qCritical() << "Integrity Check Error!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
                            }

                        } else if (static_cast<uint8_t>(packet_buf[1]) + 12 + 13 > packet_buf.size()) {
                            cipher_flag = 0;
                        }
                    }
                } else {
                    cipher_flag = 0;
                }
            } else if (static_cast<uint8_t>(packet_buf[0]) == 254) {
                if (packet_buf.size() != 1) {
                    if (static_cast<uint8_t>(packet_buf[1]) + 8 <= packet_buf.size()) {
                        temp_buf.resize(static_cast<uint8_t>(packet_buf[1]) + 8);
                        for (int position = 0; position < static_cast<uint8_t>(packet_buf[1]) + 8; position++) {
                            temp_buf[position] = packet_buf[position];
                        }
                        stream_buf.append(temp_buf);
                        packet_buf.remove(0, 8 + static_cast<uint8_t>(packet_buf[1]));
                        qCritical() << "plain packet";
                    } else if (static_cast<uint8_t>(packet_buf[1]) + 8 > packet_buf.size()) {
                        cipher_flag = 0;
                    }
                } else {
                    cipher_flag = 0;
                }
            } else {
                packet_buf.remove(0, 1);
            }
        } else {
            cipher_flag = 0;
        }
    }

    b.clear();
    b.append(stream_buf);
}
