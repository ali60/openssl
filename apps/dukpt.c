/* apps/dukpt.c */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "apps.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

# include <openssl/crypto.h>
# include <openssl/pem.h>
# include <openssl/err.h>
# include <openssl/x509_vfy.h>
# include <openssl/x509v3.h>
# include <openssl/cms.h>

#undef PROG
#define PROG dukpt_main

/*-
 * -k                - Base Derived Key
 * -s                - Key Serial Number
 * -base64           - base64 encode output
 * -hex              - hex encode output
 */

int MAIN(int, char **);


/* DES: encrypt and decrypt known plaintext, verify result matches original plaintext
*/

static void debugdata(char* caption,unsigned char* data,int datalen)
{
    int i=0;
   BIO_printf(bio_err,"%s = ",caption);        
    for(i=0;i<datalen;i++){
        BIO_printf(bio_err,"%02X",data[i]);        
    }
   BIO_printf(bio_err,"\n");        
    
}




int generateIpek(unsigned char* bdk,const unsigned char* ksn,unsigned char* ipek)
{
    unsigned char in[8]={0} ;
    unsigned char tkey[16]={0} ;
    unsigned char iv[EVP_MAX_IV_LENGTH]={0};
    EVP_CIPHER_CTX* ctx;
    int outl;
    int i;


    ctx = EVP_CIPHER_CTX_new();
//    EVP_CIPHER_CTX_init(&ctx);
//    memcpy(tkey,"\x07\x3B\xBA\xEC\x7C\x20\xB0\xEF\x01\xE9\xC2\x34\x91\x54\xA7\x7C",16);
    memcpy(tkey,bdk,16);
    EVP_EncryptInit_ex(ctx, EVP_des_ede() , NULL, tkey, iv);
    
    memcpy(in,ksn,8);
    in[7] &=0xE0;

    EVP_EncryptUpdate(ctx, ipek, &outl, in, 8);
    for(i=0;i<4;i++){
        tkey[i] ^=0xC0;
        tkey[i+8] ^=0xC0;
    }
    EVP_EncryptInit_ex(ctx, EVP_des_ede() , NULL, tkey, iv);
    EVP_EncryptUpdate(ctx, &ipek[8], &outl, in, 8);
//    cms = CMS_encrypt(NULL, in, EVP_des_ede3_cbc(), flags);
    EVP_CIPHER_CTX_cleanup(ctx);
    return 1;
    
}

/// <summary>
/// Performs the Non-Reversable Key Generation Process according to ANSI X9.24-1:2009 A.2 Processing Algorithms - Non-reversible Key Generation Process
/// </summary>
/// <param name="key">Key used to perform the key generation</param>
/// <param name="cr1">Crypto Register 1, must contain the KSN on calling and first part of key on return</param>
/// <param name="cr2">Crypto Register 2, contains the second part of key on return</param>
static void NonReversibleKeyGenerationProcess(unsigned char* key, unsigned char* cr1, unsigned char* cr2)
{
    unsigned char keyl[8];
    unsigned char keyr[8];
    unsigned char tkey[16]={0} ;
    int i,outl;
    unsigned char iv[EVP_MAX_IV_LENGTH]={0};
    EVP_CIPHER_CTX* ctx;

    memcpy(keyl,key, 8);
    memcpy(keyr,key+8, 8);

    for(i=0;i<8;i++)
        cr2[i] = cr1[i]^keyr[i];

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_des_cbc() , keyl, iv);
    EVP_EncryptUpdate(ctx, cr2, &outl, cr2, 8);
    
    for(i=0;i<8;i++)
        cr2[i] = cr2[i]^keyr[i];


    memcpy(tkey,key,16);
    for(i=0;i<4;i++){
        tkey[i] ^=0xC0;
        tkey[i+8] ^=0xC0;
    }
    
    memcpy(keyl,tkey, 8);
    memcpy(keyr,tkey+8, 8);

    for(i=0;i<8;i++)
        cr1[i] = cr1[i]^keyr[i];
        
    EVP_EncryptInit(ctx, EVP_des_cbc() , keyl, iv);
    EVP_EncryptUpdate(ctx, cr1, &outl, cr1, 8);

    for(i=0;i<8;i++)
        cr1[i] = cr1[i]^keyr[i];
}

static int checkBitOn(unsigned char* trancount, int offset, int bit)
{
    unsigned char mask;
    if (bit < 5){
        mask = (0x10 >> bit);
        if ((trancount[offset + 0] & mask) != 0)
            return 1;
    }
    else if (bit < 13){
        mask = (0x80 >> (bit - 5));
        if ((trancount[offset + 1] & mask) != 0)
            return 1;
    }
    else if (bit < 21){
        mask = (0x80 >> (bit - 13));
        if ((trancount[offset + 2] & mask) != 0)
            return 1;
    }
    return 0;
}

static void setBitOn(unsigned char* trancount, int offset, int bit)
{
    unsigned char mask;
    if (bit < 5){
        mask = (0x10 >> bit);
        trancount[offset + 0] = (trancount[offset + 0] | mask);
    }
    else if (bit < 13){
        mask = (0x80 >> (bit - 5));
        trancount[offset + 1] = (trancount[offset + 1] | mask);
    }
    else if (bit < 21){
        mask = (0x80 >> (bit - 13));
        trancount[offset + 2] = (trancount[offset + 2] | mask);
    }
}

void CalculateTransactionKey(unsigned char* bdk,const unsigned char* ksn,unsigned char* trans_key)
{
    unsigned char key[16];
    unsigned char trancount[3];
    unsigned char ksn0[10]={0};
    generateIpek(bdk,ksn,key);
    debugdata("ipek",key,16);

    memcpy(trancount,ksn+7,3);
    trancount[0]&=0x1F;

    memcpy(ksn0,ksn+2,8);
    ksn0[7] &=0xE0;


    for (int i = 0; i < 21; ++i){
        if (checkBitOn(trancount, 0, i)){
            unsigned char cr2[8]={0};
            unsigned char cr1[8]={0};
            setBitOn(ksn0, 5, i);

            memcpy(cr1,ksn0, 8);

            NonReversibleKeyGenerationProcess(key, cr1, cr2);

            memcpy(key, cr1, 8);
            memcpy(key+8, cr2, 8);
        }
    }

    memcpy(trans_key, key,16);
}

void test_dukpt()
{
    unsigned char bdk[16];
    unsigned char ksn[10];
    unsigned char key[16];
    memcpy(bdk,"\x07\x3B\xBA\xEC\x7C\x20\xB0\xEF\x01\xE9\xC2\x34\x91\x54\xA7\x7C",16);
    memcpy(ksn,"\x56\x02\x51\x01\x00\x00\x00\x81\xFF\xFF",10);
    CalculateTransactionKey(bdk,ksn,key);
    debugdata("trkey",key,16);
}



typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_KSN, OPT_ENGINE, OPT_BDK
} OPTION_CHOICE;

OPTIONS dukpt_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [flags] num\n"},
    {OPT_HELP_STR, 1, '-', "Valid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"ksn", OPT_KSN, '-', "KSN ( Key Serial Number)"},
    {"bdk", OPT_BDK, '-',"bdk"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};

int dukpt_main(int argc, char **argv)
{
    char  *prog;
    char *bdk = NULL;
    char *ksn = NULL;
    OPTION_CHOICE o;
    int   num = -1,  ret = 1;
    test_dukpt();

    prog = opt_init(argc, argv, dukpt_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(rand_options);
            ret = 0;
            goto end;
        case OPT_KSN:
            ksn = opt_arg();
            break;
        case OPT_ENGINE:
            (void)setup_engine(opt_arg(), 0);
            break;
        case OPT_BDK:
            bdk = opt_arg();
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argc != 1 || !opt_int(argv[0], &num) || num < 0)
        goto opthelp;


    ret = 0;
    BIO_printf(bio_err, "BDK =%s\n",bdk);
    BIO_printf(bio_err, "KSN =%s\n",ksn);

 end:
    if (ret != 0)
        ERR_print_errors(bio_err);
    return (ret);
}
