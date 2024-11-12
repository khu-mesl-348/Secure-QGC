
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "mc.h"
#include <QtCore/QSettings>

void mesl_qgc_encrypt(const QByteArray& data, QByteArray& Edata);
void mesl_qgc_decrypt(QByteArray& b,QByteArray& packet_buf);
void mesl_qgc_integrity_gen(const QByteArray& data, QByteArray& Edata);
void mesl_qgc_integrity_check(QByteArray& b,QByteArray& packet_buf);
