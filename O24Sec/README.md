`$ python main.py <data_path> <save_path>`
### return : 
- <save_path>/encrypt/ : encryption events with category(0 ~ 3 : inner-outer, server-client)
- <save_path>/plain/ : unencryption events with category(0 ~ 3 : inner-outer, server-client) 
- <save_path>/{object}_result.csv : The Result of clustered events   


### 👇 Follow this exe video 👇


![](https://github.com/kookmin-sw/capstone-2021-18/tree/master/video_preprocessing.gif "Logo Title Text 1")
![](https://github.com/spectator05/capstone-2021-18/blob/master/image/video_preprocessing.gif  "Logo Title Text 1")

    
        
 ### ✅ Result CSV(보안상 문제가 될 수 있는 부분은 블러처리 되어 있습니다.)
    
    
 ![](https://github.com/MinSong1227/capstone-2021-18/blob/master/image/csv_result.jpg "Logo Title Text 1")
    
#### Column:   
 Cluster : Cluster Index   
 Result : 해당 탐지에 대한 보안 전문가의 오탐(0) 정탐(1) 라벨   
 _id : 해당 이벤트에 대한 해시 구분    
 DetectName : 기존에 IPS장비에서 이벤트를 탐지했을때의 탐지 명    
 Payload : 이벤트의 어플리케이션 페이로드    
 Label_Purity : 해당 클러스터에 라벨들이 얼마나 일관적인지(1 ~ 0)   
 DetectName_Purity : 해당 클러스터에 DetectName이 얼마나 일관적인지(1 ~ 0)   
 Diffrent : 대표 벡터와 각 이벤트들의 단어 차이점   
   
