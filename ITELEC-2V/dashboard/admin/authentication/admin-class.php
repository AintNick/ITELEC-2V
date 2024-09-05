<?php
require_once __DIR__.'/../../../config/setting-configurition.ph';
require_once __DIR__.'/../../../database/dbconnection.php';


class ADMIN
{
    private $conn;
    public function __construct()
    {
        $database = new database();
        $this->conn = $database->dbconnection();
    }


    public function addAdmin($csrf_token, $username, $email ,$password)
    {
$stmt = $this->conn ->prepare("SELECT * FROM user WHERE email = :email");
$stmt->execute(array("email" => $email));


if($stmt->rowCount() > 0){
    echo "<script>alert('Email already exists.); window.location.href = '../../../'l</script";
    exit;
}


if (!isset($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token))
    echo "<script>alert('Invalid CSRF token.); window.location.href = '../../../'l</script";
    exit;


    if (isset($_SESSION['csrf_token'])) {
    unset($_SESSION['csrf_token']);
}



    $hash_password = password_hash($password, PASSWORD_DEFAULT);
}


public function editAdmin($csrf_token, $username, $email, $password)
{
    // Assuming $this->runQuery is a method that prepares SQL statements
    $stmt = $this->runQuery('INSERT INTO user (username, email, password) VALUES (:username, :email, :password)');

    // Create a hashed password
    $hash_password = password_hash($password, PASSWORD_BCRYPT);

    // Execute the query with the parameters
    $exec = $stmt->execute(array(
        ":username" => $username,
        ":email" => $email,
        ":password" => $hash_password
    ));

    

    if ($exec){
        echo "<script>alert('Admin Added Successfully.); window.location.href = '../../../'l</script";
        exit;
    }else{
            echo "<script>alert('Error Adding Admin.); window.location.href = '../../../'l</script";






    }   

    }


    public function adminSignin($email, $password, $csrf_token){


    }


    public function adminSignout()
    {


    }


    public function logs($activity, $user_id )
    {


    }


    public function runQuery($sql)
    {
        $stmt = $this->conn->prepare($sql);
        return $stmt;
    }

    
}


if(isset($_POST['btn-signup'])){
    $csrf_token = trim($_POST['csrf_token']);
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);


    $addAdmin = new ADMIN();
    $addAdmin-> addAdmin($csrf_token, $username, $email ,$password);
}
?>
