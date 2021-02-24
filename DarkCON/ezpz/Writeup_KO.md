# [DarkCON CTF] ezpz

## Info

+ 48 solves / 470 points

Some easy android for ya :)

## Summary

+ dex2jar
+ ADB logcat

## Exploit

**Decompilation**

apk가 주어지므로 압축을 풀고 classes.dex 파일들을 dex2jar로 변환해주자.

```
l0tus@DESKTOP-6V5O4LP:/mnt/c/Users/SKYPC364/documents/dex2jar-2.0$ ./d2j-dex2jar.sh -f ./classes.dex
dex2jar ./classes.dex -> ./classes-dex2jar.jar
Detail Error Information in File ./classes-error.zip
Please report this file to http://code.google.com/p/dex2jar/issues/entry if possible.
l0tus@DESKTOP-6V5O4LP:/mnt/c/Users/SKYPC364/documents/dex2jar-2.0$ ./d2j-dex2jar.sh -f ./classes2.dex
dex2jar ./classes2.dex -> ./classes2-dex2jar.jar
l0tus@DESKTOP-6V5O4LP:/mnt/c/Users/SKYPC364/documents/dex2jar-2.0$ ./d2j-dex2jar.sh -f ./classes3.dex
dex2jar ./classes3.dex -> ./classes3-dex2jar.jar
Detail Error Information in File ./classes3-error.zip
Please report this file to http://code.google.com/p/dex2jar/issues/entry if possible.
```

AndroidManifest.xml을 열면 com.application.ezpz.MainActivity를 실행할 때 호출하는 것을 알 수 있다.

jd-gui를 통해 jar 파일 내부를 살펴보자.

```java
public class MainActivity extends AppCompatActivity {
  EditText button;
  
  Button editText;
  
  int flag_counter = 0;
  
  protected void onCreate(Bundle paramBundle) {
    super.onCreate(paramBundle);
    setContentView(2131427356);
    this.editText = (Button)findViewById(2131231042);
    this.button = (EditText)findViewById(2131230881);
    if (!(new uselessClass()).flagCheckerxD((Activity)this))
      Toast.makeText(getApplicationContext(), "Ya need internet connection for the flag", 0).show(); 
    final String[] YEET = (new whyAmIHere()).isThisWhatUWant();
    this.editText.setOnClickListener(new View.OnClickListener() {
          public void onClick(View param1View) {
            float[] arrayOfFloat = (new uselessClass()).toWhereEver(param1View, context);
            if (MainActivity.this.button.getText().toString() != null) {
              if (MainActivity.this.flag_counter < 500) {
                MainActivity mainActivity = MainActivity.this;
                mainActivity.flag_counter++;
                MainActivity.this.editText.setX(arrayOfFloat[0]);
                MainActivity.this.editText.setY(arrayOfFloat[1]);
                Toast.makeText(MainActivity.this.getApplicationContext(), "Lets Play :)", 0).show();
                return;
              } 
              if (YEET[0].equals(MainActivity.this.button.getText().toString())) {
                Toast.makeText(MainActivity.this.getApplicationContext(), "Well thats the  Correct Flag", 0).show();
                return;
              } 
              Toast.makeText(MainActivity.this.getApplicationContext(), "Damn...500 times? are u kidding me", 0).show();
              return;
            } 
            Toast.makeText((Context)context, "Gib flag or get out", 0).show();
          }
        });
  }
}
```

MainActivity는 whyAmIHere를 호출한 뒤 버튼을 클릭할 때마다 위치를 랜덤하게 변경하는 역할을 한다.

```java
public class whyAmIHere {
  public String[] isThisWhatUWant() {
    final String[] justAWaytoMakeAsynctoSync = new String[1];
    arrayOfString[0] = "";
    FirebaseFirestore.getInstance().collection("A_Collection_Is_A_Set_Of_Data").get().addOnSuccessListener(new OnSuccessListener<QuerySnapshot>() {
          public void onSuccess(QuerySnapshot param1QuerySnapshot) {
            for (DocumentSnapshot documentSnapshot : param1QuerySnapshot) {
              justAWaytoMakeAsynctoSync[0] = documentSnapshot.getString("Points");
              Log.d("TypicalLogcat", justAWaytoMakeAsynctoSync[0]);
            } 
          }
        }).addOnFailureListener(new OnFailureListener() {
          public void onFailure(Exception param1Exception) {
            justAWaytoMakeAsynctoSync[0] = "Something Failed,Maybe Contact Author?";
          }
        });
    return arrayOfString;
  }
}
```

whyAmIHere에서 Log.d를 통해 로그를 전송하는 것이 보인다.

**ADB**

모바일 환경에서 디버깅을 진행하기 위해 Android Debug Bridge를 사용하자. 스마트폰의 개발자 옵션에 들어가 'USB 디버깅'을 허용해준 후 USB 케이블을 이용해 스마트폰을 컴퓨터에 연결해주자.

스마트폰에서 ezpz를 실행한 후 logcat을 이용해 로그를 조회해보면 다음과 같이 flag를 얻을 수 있다.

```
PS C:\Program Files (x86)\ClockworkMod\Universal Adb Driver> ./adb.exe logcat -s TypicalLogcat:*
--------- beginning of crash
--------- beginning of main
02-24 22:39:43.642  3538  3538 D TypicalLogcat: darkCON{d3bug_m5g_1n_pr0duct10n_1s_b4d}
02-24 22:40:39.114  3538  3538 D TypicalLogcat: darkCON{d3bug_m5g_1n_pr0duct10n_1s_b4d}
--------- beginning of system
02-24 22:47:56.487  6104  6104 D TypicalLogcat: darkCON{d3bug_m5g_1n_pr0duct10n_1s_b4d}
```

## Flag

+ darkCON{d3bug_m5g_1n_pr0duct10n_1s_b4d}