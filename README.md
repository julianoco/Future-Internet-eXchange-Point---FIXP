<h1 align="right">About FIXP</h1>
<hr>
<p align="justify">
  The Internet was designed to meet needs different from those of today. Modern applications have new demands that the network cannot meet due to technical limitations. One of the difficulties of the Internet is the lack of flexibility in implementing new network-layer services, which limits its evolution. This scenario motivated the development of new designs, commonly referred to as FIA. These are disjoint architectures that, through their designs, propose mechanisms to advance various aspects of communication, such as network-layer flexibility, mobility, multicasting, QoS, connectivity, QoE, and security. Despite the demand, the lack of implementation of these new architectures in high-performance networks makes it difficult to assess the maturity of their communication characteristics for specific scenarios and applications. On the other hand, due to the ubiquity of the traditional Internet, replacing the TCP/IP architecture is not feasible. A single communication network or logical exchange point that integrates FIA and the TCP/IP architecture without compromising their architectural principles (resources and mechanisms) creates a path to provide networks that meet the demands of current and future applications. This paper extends the theoretical discussions on the FIXP. It presents it as a candidate for this single network or logical exchange point that allows the coexistence of diverse Internet architectures. It also performs a qualitative and quantitative analysis of the FIXP by evaluating the capacity of the FIXP to incorporate new Internet architectures, the effectiveness of the FIXP implementation in current networks, and the performance of communication of applications of different Internet architectures, considering the user experience. Evaluations demonstrate the FIXP architecture conceptually by executing selected use cases in which applications from different FIA coexist in the same communication environment. In addition, the work presents the details of integrating the ETArch and IP architectures in the FIXP network, aiming to facilitate the future incorporation of other Internet architectures into this infrastructure. Regarding related work, the collection enables comparison with FIXP, positioning it at the state of the art as the only infrastructure that does not add overhead to switching devices through interoperability processes and/or protocol stack development. Furthermore, FIXP's architectural principles differ from the solutions of related works. Because of this, the difficulty of integrating new FIA into FIXP is low or medium compared to theirs. The absence of additional overloading processes and the low to medium difficulty in integrating new FIA facilitates the implementation of the FIXP in current networks. Finally, this work also presents the FIXP's perspective on multi-architecture applications, which provide services that utilize different Internet architectures.
</p>
<h1 align="right">Evaluation scenario</h1>
<hr>

<p align="justify">
The evaluation scenario in Figure XX has two communicating entities (Entities 01 and 02), two controllers (IP and ETArch controllers), and five switches FIXP (s01 to s05). The figure does not describe the Internet architecture and the applications that Entities 01 and 02 represent, as this information depends on the specific use case[cite: 5].  
</p>

<p align="center">
<img width="35%" alt="image" src="https://github.com/user-attachments/assets/2ba29a5e-287a-49fd-afea-c43571b2c476" />
</p>

<p align="justify">
The entities represent Chat/IP if the use case refers to the Chat/IP application, Video/ETArch if the use case refers to the Video/ETArch application, and so on. However, the location of the entities remains the same regardless of the use case being executed.
</p>
<p align="justify">
An addendum: the switches in the evaluation scenario are software devices, named BmV2. BmV2 was not designed to be a production-level software switch. Nevertheless, it meets our needs: to demonstrate the guiding principles of FIXP and to analyze the behavior of FIXP in two selected use cases: sending IP messages through a CHAT/IP application and sending ETArch messages through a CHAT/ETARCH application.
</p>

<h1 align="right">Virtual machine configuration</h1>
<hr>
<p align="justify">
  Each entity in the evaluation scenario corresponds to a virtual machine; therefore, we need to configure 10 virtual machines, one for each entity represented in Figure XXX.
</p>
<p align="justify">
  Configure each virtual machine by placing its corresponding code folder into the root directory. For instance, the Controller01 VM must contain the contents of the Controller01 folder, while the FIXP Interface VM requires the Interface folder. Apply this mapping to all remaining components.
</p>
<p align="justify">
  Use VirtualBox to configure the network interfaces shown in the tables below. For inter-VM communication, create isolated private networks using Host-Only mode with static IPs. For external Internet access, configure the interfaces in Bridge mode using dynamic IP addressing.
</p>
<p align="justify">
  The following table shows the network interface configurations.
</p>

<table align="center">
  <thead>
    <tr bgcolor="#add8e6">
      <th>Máquina Virtual</th>
      <th>NIC</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="2" align="center"><b>Entity 01</b></td>
      <td>eth0 - 192.168.171.104 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth1 - dynamic - Bridge</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td rowspan="2" align="center"><b>Entity 02</b></td>
      <td>eth0 - 192.168.184.102 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth1 - dynamic - Bridge</td>
    </tr>
    <tr>
      <td rowspan="6" align="center"><b>Switch 01</b></td>
      <td>eth0 - 192.168.171.101 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth1 - 192.168.201.101 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth2 - dynamic - Bridge</td>
    </tr>
    <tr>
      <td>eth3 - 192.168.231.101 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth4 - 192.168.11.101 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth5 - 192.168.21.101 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td rowspan="5" align="center"><b>Switch 02</b></td>
      <td>eth0 - 192.168.221.101 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth1 - 192.168.11.102 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth2 - dynamic - Bridge</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth3 - 192.168.31.102 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth4 - 192.168.71.101 - static - Only Host</td>
    </tr>
    <tr>
      <td rowspan="5" align="center"><b>Switch 03</b></td>
      <td>eth0 - 192.168.184.101 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth1 - 192.168.71.102 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth2 - dynamic - Bridge</td>
    </tr>
    <tr>
      <td>eth3 - 192.168.41.102 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth4 - 192.168.81.101 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td rowspan="5" align="center"><b>Switch 04</b></td>
      <td>eth0 - 192.168.211.101 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth1 - 192.168.81.102 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth2 - dynamic - Bridge</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth3 - 192.168.51.102 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth4 - 192.168.91.101 - static - Only Host</td>
    </tr>
    <tr>
      <td rowspan="6" align="center"><b>Switch 05</b></td>
      <td>eth0 - 192.168.191.101 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth1 - 192.168.22.101 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth2 - dynamic - Bridge</td>
    </tr>
    <tr>
      <td>eth3 - 192.168.61.102 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth4 - 192.168.91.102 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth5 - 192.168.21.102 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td rowspan="9" align="center"><b>Interface</b></td>
      <td>eth0 - 192.168.231.105 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9"><td>eth1 - 192.168.241.101 - static - Only Host</td></tr>
    <tr bgcolor="#f9f9f9"><td>eth2 - dynamic - Bridge</td></tr>
    <tr bgcolor="#f9f9f9"><td>eth3 - 192.168.251.101 - static - Only Host</td></tr>
    <tr bgcolor="#f9f9f9"><td>eth4 - 192.168.111.101 - static - Only Host</td></tr>
    <tr bgcolor="#f9f9f9"><td>eth5 - 192.168.31.101 - static - Only Host</td></tr>
    <tr bgcolor="#f9f9f9"><td>eth6 - 192.168.41.101 - static - Only Host</td></tr>
    <tr bgcolor="#f9f9f9"><td>eth7 - 192.168.51.101 - static - Only Host</td></tr>
    <tr bgcolor="#f9f9f9"><td>eth8 - 192.168.61.101 - static - Only Host</td></tr>
    <tr>
      <td rowspan="2" align="center"><b>ETArch Controller</b></td>
      <td>eth0 - 192.168.241.104 - static - Only Host</td>
    </tr>
    <tr>
      <td>eth1 - dynamic - Bridge</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td rowspan="3" align="center"><b>IP Controller</b></td>
      <td>eth0 - 192.168.111.102 - static - Only Host</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth1 - dynamic - Bridge</td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td>eth2 - 192.168.241.103 - static - Only Host</td>
    </tr>
  </tbody>
</table>

<p align="justify">
The following table details the tool configurations deployed across each virtual machine.  
</p>

<table align="center">
  <thead>
    <tr bgcolor="#add8e6">
      <th>Máquina Virtual</th>
      <th>Ferramentas Utilizadas</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="center"><b>Entity 01</b></td>
      <td>
        <ul>
          <li>Python 2.7.13 e Python 3.5.3</li>
          <li>ffmpeg version 3.2.18-0+deb9u1</li>
          <li>python-gevent (versão 1.1.2)</li>
          <li>python-protobuf (versão 3.5.2)</li>
        </ul>
      </td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td align="center"><b>Entity 02</b></td>
      <td>
        <ul>
          <li>Python 2.7.13 e Python 3.5.3</li>
          <li>ffmpeg version 3.2.18-0+deb9u1</li>
          <li>python-gevent (versão 1.1.2)</li>
          <li>python-protobuf (versão 3.5.2)</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td align="center"><b>Switches 01, 02, 03, 04 e 05</b></td>
      <td>
        <ul>
          <li>Python 2.7.12 e Python 3.5.2</li>
          <li>scapy 2.2.0</li>
          <li>bmv2 com suporte a simple_switch (1.10.0-02319548) e pi_cli_bmv2</li>
          <li>Configuração de variáveis em <code>/labs/fixp/rule_handler_server.py</code></li>
        </ul>
      </td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td align="center"><b>Interface</b></td>
      <td>
        <ul>
          <li>Python 2.7.13 e Python 3.5.3</li>
          <li>python-gevent (versão 1.1.2)</li>
          <li>python-protobuf (versão 3.5.2)</li>
          <li>scapy 2.2</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td align="center"><b>ETArch Controller</b></td>
      <td>
        <ul>
          <li>Python 2.7.13 e Python 3.5.3</li>
          <li>python-gevent (versão 1.1.2)</li>
          <li>python-protobuf (versão 3.5.2)</li>
        </ul>
      </td>
    </tr>
    <tr bgcolor="#f9f9f9">
      <td align="center"><b>IP Controller</b></td>
      <td>
        <ul>
          <li>Python 2.7.13 e Python 3.5.3</li>
          <li>python-gevent (versão 1.1.2)</li>
          <li>python-protobuf (versão 3.5.2)</li>
          <li>scapy 2.2</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>
<h1 align="right">Use Case Initialization -- Chat ETArch e Chat IP</h1>
<hr>

<p align="justify">
Follow the steps below to initialize Chat ETArch and Chat IP, which are hosted on Host 01 and Host 02, respectively.
</p>

<h3>1. Start Switches</h3>
<p>Start Switch 01 using the commands below:</p>
 <pre><code>sudo simple_switch -i 1@eth3 -i 2@eth0 -i 3@eth4 -i 4@eth5 -i 5@eth1 /home/student/labs/fixp/p4prog/fixp.json --log-file loggin
cd labs/fixp
sudo python rule_handler_server.py</code></pre>

<p>Start Switch 02 using the commands below:</p>
    <pre><code>sudo simple_switch -i 1@eth3 -i 2@eth0 -i 4@eth4 -i 3@eth1 /home/student/labs/fixp/p4prog/fixp.json --log-file loggin
cd labs/fixp
sudo python rule_handler_server.py</code></pre>

  <p>Start Switch 03 using the commands below:</p>
  <pre><code>sudo simple_switch -i 1@eth3 -i 2@eth0 -i 4@eth4 -i 3@eth1 /home/student/labs/fixp/p4prog/fixp.json --log-file loggin
  
cd labs/fixp
sudo python rule_handler_server.py</code></pre>

  <p>Start Switch 04 using the commands below:</p>
  <pre><code>sudo simple_switch -i 1@eth3 -i 2@eth0 -i 3@eth1 -i 4@eth4 /home/student/labs/fixp/p4prog/fixp.json --log-file loggin
cd labs/fixp
sudo python rule_handler_server.py</code></pre>

 <p>Start Switch 05 using the commands below:</p>
 <pre><code>sudo simple_switch -i 1@eth3 -i 2@eth0 -i 3@eth1 -i 4@eth4 -i 5@eth5 /home/student/labs/fixp/p4prog/fixp.json --log-file loggin   
cd labs/fixp
sudo python rule_handler_server.py</code></pre>



  <h3>2. Start Interface and Controllers</h3>
    <ol>
        <li>
            <strong>Start Interface 01 using the commands below:</strong>
            <pre><code>cd fixp
python switch_packet_handler.py
python controller_packet_handler.py</code></pre>
        </li>
        <li>
            <strong>Start ETArch Controller using the commands below:</strong>
            <pre><code>cd fixp/etarch/dts-server/
python dtsa.py</code></pre>
        </li>
        <li>
            <strong>Start IP Controller using the commands below:</strong>
            <pre><code>cd fixp/IP
python controllerIP.py</code></pre>
        </li>
    </ol>


 <h3>3. Execution of Applications</h3>
    <ul>
        <li>
            <strong>Start ETArch Chat on Host 01:</strong>
            <pre><code>cd fixp/etarch/dts-client/
python chat.py eth0 e1 w1</code></pre>
        </li>
        <li>
            <strong>Start ETArch Chat on Host 02:</strong>
            <pre><code>cd fixp/etarch/dts-client/
python chat.py eth0 e2 w1</code></pre>
        </li>
        <li>
            <strong>Type a message in the ETArch Chat:</strong>
            <p>Messages sent from the ETArch chat on Host 01 are received by the corresponding instance on Host 02, and vice versa.</p>
        </li>
        <li>
            <strong>Start IP Chat on Host 02:</strong>
            <pre><code>cd fixp/IP
python serverIP.py</code></pre>
        </li>
        <li>
            <strong>Start IP Chat on Host 01:</strong>
            <pre><code>cd fixp/IP
python clientIP.py</code></pre>
        </li>
        <li>
            <strong>Type a message in the IP Chat:</strong>
            <p>The IP Chat client on Host 01 initiates communication with the IP Chat server on Host 02, which subsequently acknowledges and responds to the message. This use case instantiates a basic request-response pattern, providing a conceptual demonstration of inter-host communication.</p>
        </li>

      
  </ul>






