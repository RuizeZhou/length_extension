#coding:utf-8
#22/07/26 Ruize Zhou
import utils
IV='7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e'
import numpy as np
from gmssl import sm3, func



Extend_m1 = [0 for _ in range(68)]
Extend_m2 = [0 for _i in range(64)]


def left(x,n):
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)


# def cir_left(num,left):
#     a1=num<<left
#     print('a1:',a1)
#     a2=num >>(32-left)
#     print(a2)
#     a3=a1|a2
#     print(a3)
#
#     return (num<<left) | (num >>(32-left))



def P_0(x):
    return x ^ left(x, 9) ^ left(x, 17)
def P_1(x):
    return x ^ left(x, 15) ^ left(x, 23)


def msg_extend(B_i):
    for i in range(16):
        Extend_m1[i]=int(B_i[8*i:8*i+8],16)
    for i in range(16,68):
        Extend_m1[i]=(P_1(Extend_m1[i - 16] ^ Extend_m1[i - 9] ^ left(Extend_m1[i - 3], 15)) ^ left(Extend_m1[i - 13], 7) ^ Extend_m1[i - 6])
    for i in range(64):
        Extend_m2[i]=Extend_m1[i] ^ Extend_m1[i + 4]




def pad_msg(s,n,size):
    s+='8'
    for i in range(int(n/4-1)):
        s+='0'

    ss="{:016x}".format(size)
    # print(ss)
    s+=ss
    return s
# def Pad_msg(s,n,size):
#     s+='8'
#     for i in range(int(n/4-1)):
#         s+='0'
#     ss="{:016x}".format(size)
#     print(ss)
#     s+=ss
#     return s,n

# Tj = [ 0x79cc4519, 0x7a879d8a ]
Tj=[2043430169 , 2055708042]
def find_Tj(x):
    return Tj[1] if x>15 else Tj[0]

def FFi(x,y,z,n):
    return ((x & y) | (y & z) | (x & z))  if n>15 else (x ^ y ^ z)

def GGi(x,y,z,n):
    return ((x & y) | ((~x) & z)) if n>15 else (x ^ y ^ z)




def CF(V,Bi):
    ABC= [0 for _ in range(8)]
    vi = [0 for _i in range(8)]
    for i in range(8):
        ABC[i]= int(V[8*i:8*i+8],16)
        vi[i]=ABC[i]

    for i in range(64):
        SS1= left(((left(ABC[0], 12) + ABC[4] +left(find_Tj(i), i % 32)))&0xffffffff, 7)
        SS2 = SS1 ^ left(ABC[0], 12)
        TT1=(FFi(ABC[0], ABC[1], ABC[2], i) + ABC[3] + SS2 + Extend_m2[i])&0xffffffff
        TT2= (GGi(ABC[4], ABC[5], ABC[6], i) + ABC[7] + SS1 + Extend_m1[i])&0xffffffff
        ABC[3] = ABC[2]
        ABC[2] = left(ABC[1], 9)
        ABC[1] = ABC[0]
        ABC[0] = TT1
        ABC[7] = ABC[6]
        ABC[6] = left(ABC[5], 19)
        ABC[5] = ABC[4]
        ABC[4] = P_0(TT2)

        ABC[0],ABC[1],ABC[2],ABC[3],ABC[4],ABC[5],ABC[6],ABC[7]=map(
            lambda x:x & 0xFFFFFFFF ,[ABC[0],ABC[1],ABC[2],ABC[3],ABC[4],ABC[5],ABC[6],ABC[7]])
    result=""
    for i in range(8):
        result+="{:08x}".format(vi[i]^ABC[i])

    return result


def sm3en(m,secret=''):
    m=secret+m
    size=len(m)*4
    last_len=size%512
    pad_n= 448 - last_len if last_len < 448 else 960 - last_len
    m=pad_msg(m,pad_n,size)
    block_num = (size + 64 + pad_n) // 512
    B=[]#block_num
    V=[]#block_num+1

    V+=[IV]
    for i in range(block_num):  ###block_num
        B+=[m[128*i:128*i+128]]
        # B.append(m2[(i + 1)*64:(i+2)*64])
        msg_extend(B[i])
        V+=[CF(V[i],B[i])]       #############

    return V[block_num]




# def sm3_encrypt(m,secret=''):
#     m=secret+m
#     enc_m=bytes(m,encoding='utf-8')
#     enc_m= sm3.sm3_hash(func.bytes_to_list(enc_m))
#     return enc_m


def longextend(H_m,m1,m2,secret_size=0):
    size=len(m1)*4+secret_size
    last_len=size%512

    #填充m1
    n1_pad=448-last_len if last_len<448 else 960-last_len
    # last_len<448?448-last_len:960-last_len
    m1=pad_msg(m1,n1_pad,size)

    temp=m1+m2
    # print('m18000len+m2:',temp)

    size_temp=len(temp)*4+secret_size
    last_len_temp=size_temp % 512

    n2_pad=448 - last_len_temp if last_len_temp < 448 else 960 - last_len_temp
    m2=pad_msg(m2,n2_pad,size_temp)

    size_attack=len(m2)*4
    block_num=size_attack//512

    B=[]#block_num
    V=[]#block_num+1

    V+=[H_m]
    for i in range(block_num):
        B+=[m2[128*i:128*i+128]]
        # B.append(m2[(i + 1)*64:(i+2)*64])
        msg_extend(B[i])
        V+=[CF(V[i],B[i])]

    return V[block_num]










def get_secret_size(H_m,m1,m2,secret):
    for i in range(17):
        m1_copy=m1
        m2_copy=m2

        size=len(m1_copy)*4+i
        last_len=size%512
        n_pad=448 - last_len if last_len < 448 else  960 - last_len
        m1_copy=pad_msg(m1_copy,n_pad,size)

        temp=m1_copy+m2_copy
        en_temp=sm3en(temp,secret)

        '''secret+m1800...len+m2  填充后'''
        # print('m1800...len+m2 :',temp)


        if longextend(H_m,m1,m2,i)== en_temp:
            print(i)
            return i












if __name__=='__main__':
    m1 = "72391a"
    m2 = "678bf1"

    m1_copy=m1
    m2_copy=m2
    secret='2333'


    H_m=sm3en(m1,secret)
    print('m1:',m1,'  secret||m1 加密后:',H_m)


    #得到secret长度
    true_secret_size=len(secret)*4
    guessed_secret_size=get_secret_size(H_m,m1,m2,secret)

    print('真实长度:',true_secret_size)
    print('推测长度:',guessed_secret_size)##########################3


    print('是否相等：',true_secret_size==guessed_secret_size)



    print('======================================')

    H_attack=longextend(H_m,m1,m2,guessed_secret_size)#得到的是什么？长度拓展攻击得到的加密值。
    size=len(m1)*4+true_secret_size
    last_len=size%512
    n_pad=448-last_len if last_len<448 else 960-last_len
    m1=pad_msg(m1,n_pad,size)

    temp=m1+m2

    temp2=m1
    H_real=sm3en(temp,secret)

    print('根据H(m1)和m2, 使用长度扩展攻击得到输入消息：m1||8000..len||m2 后得到的哈希值：',H_attack) #H_attack是 长度拓展攻击得到的加密值。
    print('secret||m1||8000..len||m2  的实际哈希值(直接的哈希值：):',H_real)##是 secret||m1  的哈希值



    print(H_attack==H_real)


