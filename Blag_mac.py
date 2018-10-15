"""
mirai_fp=[]
f=open("/Users/dimplegajra/Documents/expansion_improvement/mirai_fp","r")
for line in f:
       
        ip_24=line.strip().split(",")[0]
    
        mirai_fp.append(ip_24)
        
f.close()
mirai_threshold_tp=[]
f=open("/Users/dimplegajra/Documents/expansion_improvement/mirai_threshold_tp","r")
for line in f:
       
        ip_24=line.strip().split(",")[0]

        mirai_threshold_tp.append(ip_24)
        
f.close()
"""
#Importing mismanaged
mismanaged={}
f=open("/nfs_ds/users/dimple/BLAG/expansion_improvement/mismanaged_networks","r")
for line in f:
       
        ip_24=line.strip().split(",")[0]
        score=float(line.strip().split(",")[1])
        
        #print(score)
        mismanaged[ip_24]=score
f.close()
spatio_temporal={}
filling_degree={}

#fetching fd and stu unique to ip_24
f=open("//nfs_ds/users/dimple/BLAG/expansion_improvement/fd_stu_all","r")

for line in f:
      
        ip_24=line.strip().split(",")[0]
        fd=float(line.strip().split(",")[1])
        stu=float(line.strip().split(",")[2])
        spatio_temporal[ip_24]=stu
        #print(spatio_temporal)
        filling_degree[ip_24]=fd
        
f.close()
file_leg=open("/nfs_ds/users/dimple/BLAG/expansion_improvement/groud_truth_legitimate","r")
file_mal=open("/nfs_ds/users/dimple/BLAG/expansion_improvement/ground_truth_malicious","r")
gt_leg_24=[]
gt_mal_24=[]
gt_leg=[]
gt_mal=[]
#loading ground truth legitimate and malacious (ip)
for line in file_leg:
    gt_leg.append(line)
    gt_24=".".join(line.split(".")[0:3])+".0"
    gt_leg_24.append(gt_24)
    
file_leg.close()
for line in file_mal:
      gt_mal.append(line)
      gt_24=".".join(line.split(".")[0:3])+".0"
      gt_mal_24.append(gt_24)
    
file_mal.close()    
    
false_positive_count=0
true_positive_count=0    
result_tp=[]
result_fp=[]
his_Saf ={}

count=c_fp=1

data1 = open('/nfs_ds/users/dimple/BLAG/expansion_improvement/final_table20.csv',"w")

file_list=['/nfs_ds/users/dimple/BLAG/expansion_improvement/2016-09-08_blacklist','/nfs_ds/users/dimple/BLAG/expansion_improvement/2016-09-08_whitelist']

fin_d= {}
#Assigining history and safety score unique to ip
for line in file_list:
    a = open(line,"r")
    
    for data in a:
        type=data.strip().split(",")[0]
        ip1=data.strip().split(",")[1]
        score=float(data.strip().split(",")[-1])
        ip_24=".".join(ip1.split(".")[0:3])+".0"
        if type=='h':
            his_Saf[ip1]= {'hs':score}
        if type=='f':
            his_Saf[ip1]={'s':score}  
            #print(his_Saf[ip_24].values)
    a.close()
    
ip_sub={}
for file in file_list:
    c=0
    f=open(file,"r")
    for line in f:
        if c < 20000:
            c=c+1
            type=line.strip().split(",")[0]
            if type != "hf":
                continue
            ip=line.strip().split(",")[1]
            score=float(line.strip().split(",")[-1])
            ip_24=".".join(ip.split(".")[0:3])+".0"
            fp=0
            tp=0
            ms=0
            fd=0
            stu=0
            sum_fp=sum_tp=0
            try:
                ms=mismanaged[ip_24]
                                #print(ms)
                                
            except:
                ms=0
            try:
                stu=spatio_temporal[ip_24]
                                #print(stu)
            except:
                stu=0
            try:
                fd=filling_degree[ip_24]
            except:
                fd=0
            try:
                hs=his_Saf[ip]['hs']
                saf_s=his_Saf[ip]['s']
            except:
                hs=0
                saf_s=0

                #if ip is malacious
            if ip in gt_mal:
                
                tp=1
                    #fin_d[ip_24]={'ip_4':ip_24,'fd': fd,'stu' : stu,'ms':ms,'fp':fp,'sum_tp':sum_tp,'sum_fp':sum_fp, ip_sub:{'ip1':ip ,'his_s':hs,'saf_s':saf_s }}
                        
                               
            if ip in gt_leg:
                    #sum_fp=sum_fp+1
                fp=1
                    #fin_d[ip_24]={'ip_4':ip_24,'fd': fd,'stu' : stu,'ms':ms,'fp':fp,'sum_tp':sum_tp,'sum_fp':sum_fp, ip_sub:{'ip1':ip ,'his_s':hs,'saf_s':saf_s }}

               #ip not in gt_leg and mal , check parameters of its ip_24 and then add accordingly not included mirai_fp and threshold to estimate
              
            if ip_24 in gt_mal_24:
                tp=1
                    
            if ip_24 in gt_leg_24:
                fp=1
        
            else:
                fp=1
                       
            if ip_24 not in fin_d.keys():
                if fp ==1:
                    sum_fp+=1
                if tp ==1:
                    sum_tp+=1
                fin_d[ip_24]={'ip_4':ip_24,'fd': fd,'stu' : stu,'ms':ms,'sum_tp':sum_tp,'sum_fp':sum_fp, 'ip_sub':{'ip1':ip ,'his_s':hs,'saf_s':saf_s }} 
            else:
                s=str(fin_d[ip_24]['ip_sub']['saf_s'] )
                s += ',' + str(saf_s)
                fin_d[ip_24]['ip_sub']['saf_s']=s                    
                h=str(fin_d[ip_24]['ip_sub']['his_s'] )
                h += ',' + str(hs)
               
                fin_d[ip_24]['ip_sub']['his_s']=h
                i=str(fin_d[ip_24]['ip_sub']['ip1'] )
                i += ',' + str(ip) 
                fin_d[ip_24]['ip_sub']['ip1']=i  
                if fp ==1:
                    sum_fp=fin_d[ip_24]['sum_fp']+1 
                    fin_d[ip_24]['sum_fp']=sum_fp
                if tp ==1:
                    sum_tp=fin_d[ip_24]['sum_tp']+1
                    fin_d[ip_24]['sum_tp']=sum_tp 
                #data1.write(str(fin_d[ip_24]))
                #data1.write("\n")
    f.close()
        
for msg in fin_d.items():
    print(msg)
    data1.write(str(msg))
    data1.write("\n")
        

#sorting data w.r.t ip_2
#percentage of tp and fp
percentage_tp = percentage_fp =0 
data = open("/nfs_ds/users/dimple/BLAG/expansion_improvement/percentage7.csv","w")
ex_im = open("/nfs_ds/users/dimple/BLAG/expansion_improvement/expan_improv","w")
for ip_24 in fin_d:
    per_tp = fin_d[ip_24]['sum_tp']
    per_fp = fin_d[ip_24]['sum_fp']
    total = per_tp+per_fp
    print(per_tp, per_fp)
    #per_tp = ip_24['ip_24']['sum_tp']
    #per_fp = ip_24['ip_24']['sum_fp']
    try:
        percentage_tp=(per_tp/total)*100
        percentage_fp=(per_fp/total)*100 
    except:
        print("division by zero")
       
    final = [ip_24,percentage_tp,percentage_fp]    
    print(final)
    data.write(str(final))
    data.write("\n")
   #print(data)
data1.close()

