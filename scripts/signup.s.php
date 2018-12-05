<?php
if(isset($_POST['continue'])){

  require 'dbh.s.php';

  $fName = $_POST['firstName'];
  $mName = $_POST['midName'];
  $lName = $_POST['lastName'];
  $email = $_POST["email"];
  $pwd = $_POST['password'];
  $pwdC = $_POST['confirmPassword'];
  $add1 = $_POST["address1"];
  $add2 = $_POST["address2"];
  $city = $_POST["city"];
  $zip = $_POST["zip"];
  $state = $_POST["state"];
  $phn = $_POST["phNo"];
  $about = $_POST["aboutUs"];

  if(empty($fName) || empty($lName) || empty($email) || empty($pwd) || empty($pwdC) || empty($add1) || empty($city) || empty($zip) || empty($state) || empty($phn) || empty($about)){
    //change signup.php to signup.html for this to work with the main project.
    header("Location: ../signup.html?error=emptyfields&firstName=".$fName."&midName=".$mName."&lasName=".$lName."&email=".$email."&address1=".$add1."&address2=".$add2."&city=".$city."&zip=".$zip."&state=".$state."&phNo=".$lphn."&aboutUs=".$about);
    exit();
  }
  else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    header("Location: ../signup.html?error=invaliduidmail");
    exit();
  }
  // We check if the repeated password is NOT the same.
  else if ($password !== $passwordRepeat) {
    header("Location: ../signup.html?error=passwordcheck&uid=".$username."&mail=".$email);
    exit();
  }
  else {

    // We also need to include another error handler here that checks whether or the username is already taken. We HAVE to do this using prepared statements because it is safer!

    // First we create the statement that searches our database table to check for any identical usernames.
    $sql = "SELECT emailUser FROM users WHERE emailUser=?;";
    // We create a prepared statement.
    $stmt = mysqli_stmt_init($conn);
    // Then we prepare our SQL statement AND check if there are any errors with it.
    if (!mysqli_stmt_prepare($stmt, $sql)) {
      // If there is an error we send the user back to the signup page.
      header("Location: ../signup.html?error=sqlerror");
      exit();
    }
    else {
      // Next we need to bind the type of parameters we expect to pass into the statement, and bind the data from the user.
      // In case you need to know, "s" means "string", "i" means "integer", "b" means "blob", "d" means "double".
      mysqli_stmt_bind_param($stmt, "s", $email);
      // Then we execute the prepared statement and send it to the database!
      mysqli_stmt_execute($stmt);
      // Then we store the result from the statement.
      mysqli_stmt_store_result($stmt);
      // Then we get the number of result we received from our statement. This tells us whether the email already exists or not!
      $resultCount = mysqli_stmt_num_rows($stmt);
      // Then we close the prepared statement!
      mysqli_stmt_close($stmt);
      // Here we check if the email exists.
      if ($resultCount > 0) {
        header("Location: ../signup.html?error=usertaken&firstName=".$fName."&midName=".$mName."&lasName=".$lName."&address1=".$add1."&address2=".$add2."&city=".$city."&zip=".$zip."&state=".$state."&phNo=".$lphn."&aboutUs=".$about);
        exit();
      }
    //i added this here braket because i thout i might need it
    //}
    else {
      // If we got to this point, it means the user didn't make an error! :)

      // Next thing we do is to prepare the SQL statement that will insert the users info into the database. We HAVE to do this using prepared statements to make this process more secure. DON'T JUST SEND THE RAW DATA FROM THE USER DIRECTLY INTO THE DATABASE!

      // Prepared statements works by us sending SQL to the database first, and then later we fill in the placeholders (this is a placeholder -> ?) by sending the users data.
      $sql = "INSERT INTO users (emailUser, pwdUser, firstName, midName, lastName, address, address2, ZIPcode, city, state, phn, aboutUs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
      // Here we initialize a new statement using the connection from the dbh.inc.php file.
      $stmt = mysqli_stmt_init($conn);
      // Then we prepare our SQL statement AND check if there are any errors with it.
      if (!mysqli_stmt_prepare($stmt, $sql)) {
        // If there is an error we send the user back to the signup page.
        header("Location: ../signup.html?error=sqlerror");
        exit();
      }
      else {

        // If there is no error then we continue the script!

        // Before we send ANYTHING to the database we HAVE to hash the users password to make it un-readable in case anyone gets access to our database without permission!
        // The hashing method I am going to show here, is the LATEST version and will always will be since it updates automatically. DON'T use md5 or sha256 to hash, these are old and outdated!
        $hashedPwd = password_hash($password, PASSWORD_DEFAULT);

        // Next we need to bind the type of parameters we expect to pass into the statement, and bind the data from the user.
        mysqli_stmt_bind_param($stmt, "sssssssissis", $email, $hashedPwd, $fName, $mName, $lName, $add1, $add2, $zip, $city, $state, $phn, $about);
        // Then we execute the prepared statement and send it to the database!
        // This means the user is now registered! :)
        mysqli_stmt_execute($stmt);
        // Lastly we send the user back to the signup page with a success message!
        header("Location: ../signup.html?signup=success");
        exit();

      }
    }
  }
}
mysqli_stmt_close($stmt);
mysqli_close($conn);
}
else {
// If the user tries to access this page an inproper way, we send them back to the signup page.
header("Location: ../signup.html");
exit();
}
