del .\tshooting\*.class
rmdir tshooting
del .\*.jar
javac ..\tshooting\*.java
mkdir tshooting
move ..\tshooting\*.class .\tshooting
jar cvfe Checkciphers.jar tshooting.Checkciphers .\tshooting\*.class
del .\tshooting\*.class
rmdir tshooting
move Checkciphers.jar ..\