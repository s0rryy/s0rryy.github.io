---
layout: ../layouts/FriendsLayout.astro
title: "Friends"
---

<meta name="referrer" content="no-referrer" />
<div class="post-body">
   <div id="links">
      <style>
         .links-content{
         margin-top:1rem;
         }
         .link-navigation::after {
         content: " ";
         display: block;
         clear: both;
         }
         .card {
         width: 45%;
         font-size: 1rem;
         padding: 10px 20px;
         border-radius: 4px;
         transition-duration: 0.15s;
         margin-bottom: 1rem;
         display:flex;
         }
         .card:nth-child(odd) {
         float: left;
         }
         .card:nth-child(even) {
         float: right;
         }
         .card:hover {
         transform: scale(1.1);
         box-shadow: 0 2px 6px 0 rgba(0, 0, 0, 0.12), 0 0 6px 0 rgba(0, 0, 0, 0.04);
         }
         .card a {
         border:none;
         }
         .card .ava {
         width: 3rem!important;
         height: 3rem!important;
         margin:0!important;
         margin-right: 1em!important;
         border-radius:4px;
         }
         .card .card-header {
         font-style: italic;
         overflow: hidden;
         width: 100%;
         }
         .card .card-header a {
         font-style: normal;
         color: #2bbc8a;
         font-weight: bold;
         text-decoration: none;
         }
         .card .card-header a:hover {
         color: #d480aa;
         text-decoration: none;
         }
         .card .card-header .info {
         font-style:normal;
         color:#a3a3a3;
         font-size:14px;
         min-width: 0;
         overflow: hidden;
         white-space: nowrap;
         }
      </style>
      <div class="links-content">
         <div class="link-navigation">
          <!-- 友链模板 -->
          <!-- <div class="card">
            <img class="ava" src="{avatarurl}" />
            <div class="card-header">
                <div>
                  <a href="{link}">{name}</a>
                </div>
                <div class="info">{description}</div>
            </div>
          </div> -->
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2024/jpeg/23002651/1708341663229-c76b3390-f6b9-4301-97a6-3b4a91658b2b.jpeg" />
            <div class="card-header">
                <div>
                  <a href="https://s0rry.cn">s0rry</a>
                </div>
                <div class="info">qwq</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://blog.ras-al-ghul.cn/upload/2022/03/jev0n-e00d17691c6143ff8f0deebe3ff164c9.jpg" />
            <div class="card-header">
                <div>
                  <a href="https://jev0n.com/">Jev0n</a>
                </div>
                <div class="info">伟牛牛！！</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://d33b4t0.com/img/favicon.jpg" />
            <div class="card-header">
                <div>
                  <a href="https://d33b4t0.com/">d33b4t0</a>
                </div>
                <div class="info">dbt到底是怎么学的密码啊</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://blog.ras-al-ghul.cn/upload/2022/03/favicon-993d138efc2a4f81848d342d836d073c.jpg" />
            <div class="card-header">
                <div>
                  <a href="https://blog.ras-al-ghul.cn/">RasAlGhul</a>
                </div>
                <div class="info">不想学Iot的web萌新不是好机电人。</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://pic.pysnow.cn/avator.png" />
            <div class="card-header">
                <div>
                  <a href="https://www.pysnow.cn/">pysnow</a>
                </div>
                <div class="info">要成为全栈的web手</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2024/jpeg/32634994/1706793182327-8ff9b1a8-dc18-480c-8c75-018fbe3d0243.jpeg" />
            <div class="card-header">
                <div>
                  <a href="https://boogipop.com/">Boogipop</a>
                </div>
                <div class="info">速通web，新的神</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://oslike.github.io/img/txbynq.jpg" />
            <div class="card-header">
                <div>
                  <a href="https://oslike.github.io/">OSLike</a>
                </div>
                <div class="info">OSLike</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://csc8.github.io/img/avatar.jpg" />
            <div class="card-header">
                <div>
                  <a href="https://csc8.github.io/">Csc8</a>
                </div>
                <div class="info">二进制爷</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://pic.cnblogs.com/avatar/2696005/20211221153654.png" />
            <div class="card-header">
                <div>
                  <a href="https://www.cnblogs.com/FW-ltlly">ltlly</a>
                </div>
                <div class="info">洛天琉璃依！</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://pic.cnblogs.com/avatar/1673511/20200206160739.png" />
            <div class="card-header">
                <div>
                  <a href="https://www.cnblogs.com/hed10ne">二氢茉莉酮酸甲酯</a>
                </div>
                <div class="info">主攻抽象方向</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2023/jpeg/26096065/1682879545149-avatar/62804dd5-afe2-46d8-8c9d-9e9b6999c116.jpeg" />
            <div class="card-header">
                <div>
                  <a href="https://www.yuque.com/misery333">m1sery</a>
                </div>
                <div class="info">喜欢扛着小主机打比赛？</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://picx.zhimg.com/v2-ff6b175126b8ec87b26b5ac64f4d6529_xl.jpg" />
            <div class="card-header">
                <div>
                  <a href="https://jonathanbest7.github.io/">bj777</a>
                </div>
                <div class="info">syc的师傅</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://arsenetang.com/images/pika2.jpg" />
            <div class="card-header">
                <div>
                  <a href="http://arsenetang.com/">Tang</a>
                </div>
                <div class="info">这可是汤神啊！！！</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://ppppz.net/img/Friends/P.Z.jpg" />
            <div class="card-header">
                <div>
                  <a href="https://ppppz.net/">Pz</a>
                </div>
                <div class="info">B站关注水番正文喵~</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://www.fup1p1.cn/upload/2022/10/QQ%E5%9B%BE%E7%89%8720221024131344.jpg" />
            <div class="card-header">
                <div>
                  <a href="https://www.fup1p1.cn/">fup1p1</a>
                </div>
                <div class="info">他叫傅皮皮（</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://s1.locimg.com/2024/05/11/840b1bca24d25.jpeg" />
            <div class="card-header">
                <div>
                  <a href="https://infernity.top/">infernity</a>
                </div>
                <div class="info">厉害的学弟，我们叫他鸡哥</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2024/jpeg/23002651/1708333700748-3372e655-8e2b-42be-bbe4-265521cfe217.jpeg" />
            <div class="card-header">
                <div>
                  <a href="">FallW1nd</a>
                </div>
                <div class="info">阿win的站怎么经常挂掉</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2024/jpeg/23002651/1708333700748-3372e655-8e2b-42be-bbe4-265521cfe217.jpeg" />
            <div class="card-header">
                <div>
                  <a href="https://ph0ebus.github.io/">ph0ebus</a>
                </div>
                <div class="info">ph0ebus</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2024/jpeg/23002651/1708333700748-3372e655-8e2b-42be-bbe4-265521cfe217.jpeg" />
            <div class="card-header">
                <div>
                  <a href="">novic4</a>
                </div>
                <div class="info">学无止境</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2024/jpeg/23002651/1708333700748-3372e655-8e2b-42be-bbe4-265521cfe217.jpeg" />
            <div class="card-header">
                <div>
                  <a href="">scr1pt</a>
                </div>
                <div class="info">scr1pt爷，魔王S+</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2024/jpeg/23002651/1708333700748-3372e655-8e2b-42be-bbe4-265521cfe217.jpeg" />
            <div class="card-header">
                <div>
                  <a href="">eeee</a>
                </div>
                <div class="info">e宝的杯里有水果</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2024/jpeg/23002651/1708333700748-3372e655-8e2b-42be-bbe4-265521cfe217.jpeg" />
            <div class="card-header">
                <div>
                  <a href="">LTLT</a>
                </div>
                <div class="info">想造飞机想写小说想去旅游就是不想打CTF的web狗</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2024/jpeg/23002651/1708333700748-3372e655-8e2b-42be-bbe4-265521cfe217.jpeg" />
            <div class="card-header">
                <div>
                  <a href="https://dstbp.cn/">DSTBP</a>
                </div>
                <div class="info">安卓潮人</div>
            </div>
          </div>
          <div class="card">
            <img class="ava" src="https://cdn.nlark.com/yuque/0/2024/jpeg/23002651/1708333700748-3372e655-8e2b-42be-bbe4-265521cfe217.jpeg" />
            <div class="card-header">
                <div>
                  <a href="">jiangnaij</a>
                </div>
                <div class="info">弱口令大师</div>
            </div>
          </div>
         </div>
      </div>
   </div>
</div>
