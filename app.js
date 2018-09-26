

var express = require('express');
var session = require('express-session');
var MYSQLStore = require('express-mysql-session')(session);
var bodyParser = require('body-parser');
var mysql = require('mysql');
var app = express();
var bkfd2Password = require("pbkdf2-password");
var hasher = bkfd2Password();
var AWS = require('aws-sdk');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var methodOverride = require('method-override');

var ec2 = new AWS.EC2();
var s3 = new AWS.S3();
var nodemailer = require('nodemailer'); //메일 보내기 기능(비밀번호 찾기)
var formidable = require('formidable');
var sha256 = require('sha256');

app.set('view engine', 'jade');
app.set('views', './views');
Object.assign = require('object-assign');

app.use(methodOverride('_method')); // PUT, DELETE를 지원 안 하는 클라이언트를 위해
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: false })); // bodyPaser를 연결시킴

app.use(session({
    secret: '!@#FD@$#A2323aaa@@!@#$%',
    resave: false,
    saveUninitialized: true,
    store:new MYSQLStore({

        host: 'localhost',
        port: 3306,
        user: 'root',
        password: '******',
        database: 'user_db'
    })
}));

app.use(passport.initialize());
app.use(passport.session()); // 이 코드는 세션설정 뒤에 붙어야한다.

//디비 설정
var connection = mysql.createConnection({
    host     : 'localhost',
    user     : 'root',
    password : '*******',
    database : 'user_db'
   });

//사용자가 입력한 id, pw 확인
app.post('/login', function(req, res){

    var id = req.body.id;
    var pw = req.body.pw;

    var sql = 'SELECT * FROM user_table where user_id=?';

        connection.query(sql, [id], function(err, result, fields){
     if(err) {
         console.log(err);
     }
     else {
    
        //아이디 존재하지 않는 경우
            if(result.length == 0) {
                res.render('./login', {authType : 1});
            }

            else { //아이디는 존재하므로 비밀번호만 확인하면 된다.
            var user = result[0];
           
            //해셔가 실행될때 함수를 끈내버린다?
               hasher({password:pw,salt:user.pw_salt}, function(err, pass, salt, hash){

                    if(hash === user.pw) {
                        //인증완료
                        req.session.nickname = user.nickname;
                        req.session.Id = user.Id;
                        req.session.admin = user.admin;
                        req.session.authority = user.authority;

                        req.session.save(function(){
                            res.redirect(('./login/success');
                            return;
                        });
                    }
                    else {
                        //인증 실패
                        //비밀번호가 다른경우
                        res.render('./login', {authType : 2});
                        return;
                    }
                })
            }
    }
 });
});

//로그인 성공한 화면
app.get('/login', function(req, res){ 
    res.render('./main', {user_id: req.session.id, user_nickname: req.session.nickname, user_admin: req.session.admin});
});

//로그인 성공화면
app.get('/login/success', function(req, res) {
	res.render('./main', {user_id: req.session.id, user_nickname: req.session.nickname, user_admin: req.session.admin});
});

//로그 아웃
app.get('/logout', function(req, res){
    delete req.session.nickname;
    delete req.session.Id;
    delete req.session.admin;
    delete req.session.authority;
    req.session.save(function(){
        res.render('./login', {authType : 0 });
    })
});

//회원 가입
app.post('/join', function(req, res) {

    var id = req.body.uid;
    var pw = req.body.upw;
    var pw2 = req.body.upwc;
    var name = req.body.uname;
    var nickname = req.body.unickname;
    var gender = req.body.gender;
    var phone1 = req.body.uphone1;
    var phone2 = req.body.uphone2;
    var phone3 = req.body.uphone3;
    var email = req.body.upostcode;
    var domain = req.body.umail;

    var phone = phone1 + phone2 + phone3;

    // 비밀번호 불일치 할 경우 다시 회원가입 페이지로 이동 (이부분 어떻게 구현??)
     
      var sql = 'INSERT INTO user_table (user_id, pw, name, nickname, gender, phone, email, domain, pw_salt) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)';

      hasher({password:pw}, function(err, pass, salt, hash){

        var params = [id, hash, name, nickname, gender, phone, email, domain, salt];
        connection.query(sql, params, function(err, result, fields){

            res.render('./login', {authType : 3});
});
});
});

//비밀번호 찾기
app.post('/password', function(req, res) {

    var id = req.body.id;
    var email = req.body.email;

    var sql = "SELECT user_id from user_table where user_id = ?";
    connection.query(sql, [id], function(err, row, fiedls){
        
            if(0 < row.length) {

                var pw = Math.random().toString(36).slice(2); //임의의 문자열 생성

                hasher({password:pw}, function(err, pass, salt, hash){

                    var sql2 = "UPDATE user_table set pw=?, pw_salt=? where user_id = ?";
                    connection.query(sql2, [hash, salt, id], function(err, result, fields){

                        console.log(hash);
                        console.log(salt);
                        var smtpTransport = nodemailer.createTransport({  
                            service: 'Gmail',
                            auth: {
                                user: 'xowns4817@gmail.com',
                                pass: '*******'
                            }
                        });
                        
                        var mailOptions = {  
                            from: '김태준 <xowns4817@gmail.com>',
                            to: email,
                            subject: '새로운 비밀번호 입니다.',
                            text: '초기화된 비밀번호는 ' + pw + ' 입니다.'
                        };
                        
                        smtpTransport.sendMail(mailOptions, function(error, response){
                        
                            if (error){
                                console.log(error);
                            } else {
                                console.log("Message sent : " + response.message);
                            }
                            smtpTransport.close();
                        });
        
                        res.render('./login', {authType : 4 }); // 이메일 전송 완료
                });
             })
            }
            else {
                res.render('./login', {authType : 1 }); // 없는 아이디 입니다.
            }
    });
});

//비밀번호 변경
app.put('/password', function(req, res){

    var id = req.body.id;
    var pw_now = req.body.pw_now;
    var pw_update = req.body.pw_update;
    var pw_update2 = req.body.pw_update2;

    var sql = "SELECT user_id from user_table where user_id = ?";
    connection.query(sql, [id], function(err, row, fiedls){
        
            if(0 < row.length) {

                    var sql2 = "SELECT pw, pw_salt from user_table where user_id = ?";
                    connection.query(sql2, [id], function(err, result, fields){

                        var pw = result[0].pw;
                        var pw_salt = result[0].pw_salt;

                        hasher({password:pw_now, salt: pw_salt}, function(err, pass, salt, hash){

                        if(hash === pw) { //인증완료 -> 비밀번호 갱신

                            hasher({password:pw_update}, function(err, pass, salt, hash){
                            var sql3 = "UPDATE user_table set pw=?, pw_salt=? where user_id = ?";
                            connection.query(sql3, [hash, salt, id], function(err, result, fields){
                            res.render('./login', {authType : 5 });
                        });
                    });
                    }
                        else {
                            res.render('./login', {authType : 2}); // 비밀번호 오류
                        }
                  });
             })
        }
            else {
                res.render('./login', {authType : 1 }); // 아이디 오류
            }
    });
});

//기업분석 업로드
app.get('/company_analyze', function(req, res){

    var url = "https://s3.ap-northeast-2.amazonaws.com/company-analysis/";

    s3.listObjects({Bucket: 'company-analysis'}, function(err, data){

        if(err) console.log(err);
        console.log(data.Contents);
        res.render("./company_analysis", {user_id: req.session.Id, user_nickname: req.session.nickname, user_authority: req.session.authority, user_admin: req.session.admin, user_file: data.Contents, file_url: url});
    }) 
});

//기업분석 업로드 처리(post)
app.post('/company_analyze', function(req, res){

    if(req.session.authority === 'Y') {
    var form = new formidable.IncomingForm();
    form.parse(req, function(err, fields, files){ // 사용자가 저장한 파일은 files에 담겨있음

        var params = {
            Bucket: 'company-analysis',
            Key: files.userfile.name, // s3에 저장될 파일의 이름
            ACL: 'public-read',
            Body: require('fs').createReadStream(files.userfile.path) // 전송할 파일의 내용
        }

        s3.upload(params, function(err, data){
            if(err) console.log(err);
            else  {
               // console.log(data);
                res.redirect('/company_analyze');// 리다이렉션
            }
        })
    });
}

else {
    res.send("권한이 없는 사용자 입니다.");
}
});

//자소서 업로드
app.get('/write_introduce', function(req, res){
    var url = "https://s3.ap-northeast-2.amazonaws.com/letter-self-introduce/";

    s3.listObjects({Bucket: 'letter-self-introduce'}, function(err, data){

        if(err) console.log(err);
        console.log(data);
        res.render("./self_introduce", {user_id: req.session.Id, user_nickname: req.session.nickname, user_authority: req.session.authority, user_admin: req.session.admin, user_file: data.Contents, file_url: url});
    }) 
});

//자소서 업로드 처리(post)
app.post('/write_introduce', function(req, res){

    if(req.session.authority === 'Y') {
    var form = new formidable.IncomingForm();
    form.parse(req, function(err, fields, files){

        var params = {

            Bucket: 'letter-self-introduce',
            Key: files.userfile.name,
            ACL: 'public-read',
            Body: require('fs').createReadStream(files.userfile.path)
        }

        s3.upload(params, function(err, data){
            if(err) console.log(err);
            else  {
              //  console.log(data);
              
                res.redirect('/write_introduce');// 리다이렉션
            }
        })
    });
}

else {
    res.send("권한이 없는 사용자 입니다.");
}
});

//스터디 장소&일정관리
app.get('/schedule', function(req, res){

    res.render('./schedule', {user_nickname: req.session.nickname});
}) 

//스터디 일정 조회
app.post('/schedule_result', function(req, res) {

    var date = req.body.date;
    var time = req.body.time;

    if(req.session.authority === 'Y') {

    var sql = 'SELECT * FROM schedule where date=? AND time=?';
        connection.query(sql, [date,time], function(err, result, fields){
     if(err) {
         console.log(err);
     }
     else {
      
        if(result.length > 0) {  // 해당 날짜에 일정이 있는 경우
            res.render('./schedule_result', {result:result[0]});
        } else { // 해당 날짜에 일정이 없는 경우
            res.render('./schedule_result', {result2:'일정이 없습니다.'});
        }
    }
 });
}

else { // 권한이 없는 경우 -> 지정되지 않은 사용자
    res.send("권한이 없는 사용자 입니다.");
}
});

//게시판

//게시판 글 추가
//글 추가화면 아랫줄에 '/board/:id' 이 코드보다 board/add를 위에써줘야 된다. 만약 아래쓰면 id에 add가 걸려 오류!!
app.get('/board/add', function(req, res){
       
    if(req.session.authority === 'Y'){ //권한 있으면 게시물 작성 가능
    res.render('board_add', {user_nickname: req.session.nickname});
    }

    else {
        res.send("권한이 없는 사용자 입니다.");
    }
});

//메인화면 & 글 버튼 눌렀을때 해당 id에 해당하는 상세정보 출력
app.get(['/board', '/board/:id'], function(req, res){

        var id = req.params.id;//게시물에 대한 id

        if(id) {
            
            //조회수 불러옴
            var sql = "SELECT * from board WHERE id =?";
            connection.query(sql, [id], function(err, row, fiedls){

            var next_hits = row[0].hits + 1;   

            //조회수 1증가 -> 디비에 업로드
            var sql = 'UPDATE board SET hits =? WHERE id =?';
             connection.query(sql, [next_hits, id], function(err, row, fields) {
             
            // 업로드된 내용 출력
            var sql = 'SELECT * FROM board WHERE id=?';
            connection.query(sql, [id], function(err, results, fields) {

                    var sql2 = 'SELECT nickname, content, created FROM user_table, comment where user_table.ID = comment.comment_writer_id && comment.board_id = ? order by created DESC';
                    connection.query(sql2, [id], function(err, result_comments, fields) {
                
                        res.render('board_show', {result:results[0], comments:result_comments, user_id:req.session.Id, user_nickname: req.session.nickname, user_admin: req.session.admin});
                    });
            });
        });
        });
        } else {
             //-> 유저테이블과 게시판테이블 디비에 저장된 순서대로 join해서 닉네임 가져옴 (날짜순 내림차순)
             // title, nickname, created, hits는 게시판 출력을 위한것이고 board.id는 해당 게시물을 눌렀을때 수정할 id값을 얻기위해서
            var sql = 'select board.id, title, nickname, created, hits from user_table, board where user_table.Id = board.writer_id order by created DESC';
            connection.query(sql, function(err, results, fields){
            res.render('board_main', {results:results, user_nickname: req.session.nickname});
            });
        }
    });

//글 추가 버튼을 눌렀을 때
app.post('/board/add', function(req, res){

    var title = req.body.title;
    var content = req.body.content;
    var writer_id = req.session.Id; // req.session.Id -> user_table의 기본키
    var created = new Date();
    var hits = 0;

    var sql = 'INSERT INTO board (title, content, writer_id, created, hits) VALUES(?, ?, ?, ?, ?)';
    connection.query(sql, [title, content, writer_id, created, hits], function(err, result, fields) {
        if(err) {
            console.log(err);
            res.status(500).send('Internal Server Error');
        } else{
            res.redirect('/board/');
        }
    });
});

//글 수정 버튼 눌렀을 때
app.get(['/board/:id/edit'], function(req, res){

        var id = req.params.id;
        console.log(id);

            var sql = 'SELECT * FROM board WHERE id=?';

            connection.query(sql, [id], function(err, rows, fields){

                if(err) {
                    console.log(err);
                    res.status(500).send('Internal Server Error');
                } else {
                    res.render('board_edit', {result:rows[0], user_nickname: req.session.nickname});
                }
        });
});

//편집 완료를 눌렀을 때
app.put(['/board/:id/edit'], function(req, res){

    var id = req.params.id;
    var title = req.body.title;
    var content = req.body.content;
    // 글을 수정하면 작성일을 어떻게 처리해줘야지?
    console.log(id);
    console.log(title);
    console.log(content);

    var sql = 'UPDATE board SET title =?, content=? WHERE id =?';
    connection.query(sql, [title, content, id], function(err, results, fields){
        if(err) {
            console.log(err);
            res.status(500).send('Internal Server Error');
        } else{
            res.redirect('/board/');
        }
    });
});

//삭제 화면
app.get('/board/:id/delete', function(req, res){

    var sql = 'SELECT * FROM board';
    var id = req.params.id;

    connection.query(sql, function(err, results, fields){
        var sql = 'SELECT * FROM board WHERE id =?';

        connection.query(sql, [id], function(err, rows, fields){

            var sql = 'SELECT nickname from user_table left join board on user_table.ID = board.writer_id';
            connection.query(sql, function(err, results2, fields){
            
                if(err) {
                console.log(err);
                res.status(500).send('Internal Server Error');
            } else {
                res.render('board_delete', {results:results, results2:results2, result:rows[0], user_nickname: req.session.nickname});
            }
        });
        });
    });
});

//삭제 버튼을 눌렀을 때
app.delete('/board/:id/delete', function(req, res){

    var id = req.params.id;
    var sql = 'DELETE FROM board WHERE id=?';
    connection.query(sql, [id], function(err, results, fields){
        res.redirect('/board/');
    });
});

//댓글 쓰기
app.post('/comment/:id', function(req, res){

    var comment_writer_id = req.session.Id; // req.session.Id -> user_table의 기본키
    var content = req.body.comment;
    var board_id = req.params.id;
    var created = new Date();
    
    if(req.session.authority === 'Y'){ //권한 있으면 댓글 작성 가능
        var sql = 'INSERT INTO comment (comment_writer_id, board_id, content, created) VALUES(?, ?, ?, ?)';
        connection.query(sql, [comment_writer_id, board_id, content, created], function(err, result, fields) {
            if(err) {
                console.log(err);
                res.status(500).send('Internal Server Error');
            } else{
                res.redirect('/board/' + board_id);
            }
        });
        }
    
        else {
            res.send("권한이 없는 사용자 입니다.");
        }
});

app.listen(80, function() {
    console.log('Connected 80 port');
});
