<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Riverside Corp — Employee Directory</title>
<style>
  body { font-family: Arial, sans-serif; background: #f4f6f9; margin: 0; }
  header { background: #1a3a5c; color: #fff; padding: 16px 24px; }
  main { max-width: 480px; margin: 40px auto; background: #fff; padding: 24px;
         border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.15); }
  input[type=file] { margin: 12px 0; }
  button { background: #1a3a5c; color: #fff; border: none; padding: 8px 18px;
           border-radius: 5px; cursor: pointer; }
</style>
</head>
<body>
<header><h2>Riverside Corp Intranet</h2></header>
<main>
  <h3>Employee Photo Upload</h3>
  <p>Upload your staff directory photo (JPG/PNG).</p>
  <form action="upload.php" method="post" enctype="multipart/form-data">
    <input type="file" name="photo">
    <br>
    <button type="submit">Upload</button>
  </form>
</main>
</body>
</html>
