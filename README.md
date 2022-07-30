# 项目说明

**1.小组成员**：周睿泽。git账户名称：RuizeZhou

**2,所作项目名称：**

本项目名称为：Project: implement length extension attack for SM3

简介：实现针对sm3的长度扩展攻击，编程语言为python。

完成人：周睿泽

**3.清单：**

完成的项目：

√Project: implement the naïve birthday attack of reduced SM3 

√Project: implement the Rho method of reduced SM3

√Project: implement length extension attack for SM3, SHA256, etc.

√Project: do your best to optimize SM3 implementation (software)

√Project: Impl Merkle Tree following RFC6962

√Project: report on the application of this deduce technique in Ethereum with ECDSA

√Project: Implement sm2 with RFC6979

√Project: verify the above pitfalls with proof-of-concept code

√Project: Implement a PGP scheme with SM2

未完成的项目：

Project: Try to Implement this scheme

Project: Implement the above ECMH scheme

Project: implement sm2 2P sign with real network communication

Project: implement sm2 2P decrypt with real network communication

Project: PoC impl of the scheme, or do implement analysis by Google

Project: forge a signature to pretend that you are Satoshi

Project: send a tx on Bitcoin testnet, and parse the tx data down to every bit, better write script yourself

Project: forge a signature to pretend that you are Satoshi

Project: research report on MPT

Project: Find a key with hash value “sdu_cst_20220610” under a message composed of your name followed by your student ID. For example, “San Zhan 202000460001”.

有问题的项目及问题：\

**4.本项目具体内容：**具体内容如下





# 长度扩展

Project: implement length extension attack for SM3

## A.具体的项目代码说明

​	本项目主要使用m1的哈希值以及m2，得到消息：m1||80...0L||m2及其对应的哈希值。完成该长度扩展攻击。

​	模拟实际中的secret，由于secret长度未知，本代码第一步需要找到通过循环来查找可能的长度。

```
def get_secret_size(H_m,m1,m2,secret):
    for i in range(17):
        m1_copy=m1
        m2_copy=m2

        size=len(m1_copy)*4+i
        last_len=size%512
        n_pad=448 - last_len if last_len < 448 else  960 - last_len
        m1_copy=pad_msg(m1_copy,n_pad,size) #消息填充

        temp=m1_copy+m2_copy
        en_temp=sm3en(temp,secret)   #直接对secret||m1800...len||m2加密

        '''secret||m1800...len||m2  填充后'''
        # print('m1800...len+m2 :',temp)

        if longextend(H_m,m1,m2,i)== en_temp:
            print(i)
            return i
```

​	其中longextend函数是本项目核心，输入参数依次是：m1加密后的值H_m,m1,m2,secret长度secret_size：

```
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
```

在其中，首先根据参数进行填充消息，得到填充后的m2使用一轮h加密。所得结果函数输出可在main函数中或get_secret_size函数中与m1||80..0L||m2直接进行加密的得到的结果进行对比是否一致。





## B.运行指导

​	直接运行即可



## C.代码运行全过程截图

​		![1659117920252](C:/Users/%E5%B0%8F%E8%8A%B1%E5%AE%B6%E7%9A%84%E7%B2%BD%E5%AD%90/AppData/Roaming/Typora/typora-user-images/1659117920252.png)

​	第一行输出输入m1后得到的加密值。接下来四行是在比较真实secret长度和代码运行得到的长度。最后比对长度扩展攻击代码得到的（消息，标签值）和带入sm3算法得到的标签值，得到相等True。



## D.每个人的具体贡献说明及贡献排序

本人负责全部。

