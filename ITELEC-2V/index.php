<di?php





?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="src/css/Login.css">
</head>

<body>
    <div class="wrapper">
        <for action="">
            <div class="input-box">
        <h1>SIGN IN</h1>
    <form action="  method="POST>
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token?>">
        <input type="email" name="email" placeholder="Enter Email" required> <br>
        <input type="password" name="password" placeholder="Enter Password" required> <br>
        <button type="submit" name="btn-signin">SIGN IN</button>
        
        
    </form>
    </div>

    <div class="input-box">
    <h1>REGISTRATION</h1>
    <form action="dashboard/admin/authentication//admin-class.php"method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token?>">
        <input type="text" name= "username" placeholder="Enter Username" required> <br>
        <input type="email" name="email" placeholder="Enter Email" required> <br>
        <input type="password" name="password" placeholder="Enter Password" required> <br>
        <button type="submit" name="btn-signup">SIGN UP</button>
    </form>


</body>
</html>
