# rctf

## swiss army knife ctf task automation tool

### brought to you by the rounding error ctf team


```                                                    
                                                 dd    d     dddd                                              
                                            d    ddd   d   ddd   d                                             
                                 dddddddd   dd   d  dd d   dd  dddd       ddd                                  
                                  d     dd  dd   dd   ddd  dd    dd      dd   dd                               
                             dd   dd    dd   d   dd          ddddd      dddddd     d                           
                        d     dd   dd ddd                               d         ddddd                        
                        ddddddddd   d                                     dddd  ddd   dd                       
                   dd    dd    dd                                              dd  dddd    d                   
                    dd    dd                                                       dd     dddd                 
               d      dd                                                           dd   dd    d                
                dd     d                                                              ddd dd dd                
                 dddddd                                                                   d                    
           ddddd                                                                          d    ddddd           
         dd    dd                                                                             dd    dd         
         dd     dd                                                                           dd     dd         
          dd   dd                                                                             dd   dd          
            ddd                                                                                 ddd            
     ddddd                                                                                           ddddd     
     d   dddd                                                                                     dddd   d     
    ddd dd                                                                                           dd  dd    
      ddddd                                                                                         dd dd      
                                         NNNNNNNNNNNNNN                NNN                          d          
                                     NNNNNNNNNNNNNNNNNN             NNNNNNN                                    
                              NN  NNNNNNNNNNN      NNNNN      NNNNNNNNNNNN                                     
                              NNN NNNNNN           NNNNNN NNNNNNNNNNNNNN                                       
                               NNN NN       NNNNNNNNNNNNNN NNNNNNNNN                                           
                                NNN     NNNNNNNNNNNNNNNNNNNNNNNNNNNN                                           
                                 NNN NNNNNNNNNNNN           NNNNNNNNNNNNNNN                                    
                                 NNN NNNNNNNNNNNNNNN            NNNNNNNNNNNNNNN                                
   dd                             NNN  NNNNNNNNNNNNNNNNN            NNNNNNNNNNNN                          dd   
  dddd                             NNN          NNNNNNNNN NNNNNNNNNNNNNNNNNNNN                           dddd  
   dd                               NNN            NNNNNNN NNNNNNNNNNNNNNN       N                        dd   
                                     NNN      NNNNNNNNNNNNN NNNNNN            NNNNN                            
                                     NNN   NNNNNNNNNNNNNNN   NNNNN        NNNNNNNNN                            
                                      NNN NNNNNNNN           NNNNNNNNNNNNNNNNNNNN                              
                                       NNN NNN                NNNNNNNNNNNNNNN                                  
                                        NNN                      NNN                                           
                                         NNN                                                                   
                                         NNN                                                                   
          d                               NNN                                                                  
      dd dd                                NNN                                                      ddddd      
    dd  dd                                  NNN                                                      dd ddd    
     d   dddd                                NNN                                                  dddd   d     
     ddddd                                   NNN                                                     ddddd     
            ddd                               NNN                                               ddd            
          dd   dd                                                                             dd   dd          
         dd     dd                                                                           dd     dd         
         dd    dd                                                                             dd    dd         
           ddddd    d                                                                          ddddd           
                    d                                                                   dddddd                 
                dd dd ddd                                                              d     dd                
                d    dd   dd                                                           dd      d               
                 dddd     dd                                                       dd    dd                    
                   d    dddd  dd                                              dd    dd    dd                   
                       dd   ddd  dddd                                     d   ddddddddd                        
                        ddddd         d                               ddd dd   dd     d                        
                           d     dddddd      ddddd          dd   d   dd    dd   dd                             
                               dd   dd      dd    dd  ddd   dd   dd  dd     d                                  
                                  ddd       dddd  dd   d dd  d   dd   dddddddd                                 
                                             d   ddd   d   ddd    d                                            
                                              dddd     d    dd                                                 
```

## building from source

```
$ go build
```

## installation

```
$ sudo cp ./rctf /usr/local/bin
```

Other options are available.

## ~/.config/rctf

```
{
  "ghidrainstallpath": "/path/to/ghidra/install",
  "ghidraprojectpath": "ghidra_project_folder_name_default_is_ghidra",
  "pwnscriptname": "custom-pwn-script-name.py"
}
```