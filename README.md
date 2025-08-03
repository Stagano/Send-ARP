#Modulation ARP Table (main.cpp)

  send-arp <interpace> <sender ip> <target ip>

  **[ARP Spoofing Process]**
  
  <img width="462" height="150" alt="image" src="https://github.com/user-attachments/assets/01d083a4-f8e4-4fa4-9ab1-b6ddd8110176" />

  Attacker가 A와 B 중간에서 A를 향해서는 (B)의 IP Address에 대한 mac address를
  자신의 mac address로 알려주고, B를 향해서는 (A)의 IP Address와 자신의 mac address를 알려줌
  즉, 중간에서 정상적인 mac address 교환을 자신의 mac address로 바꿔서 알려주면서 과정을 진행함.

  **[ARB Header]**
  <br><- - - - - - - - - - - - - - - - - - - - -32 bits- - - - - - - - - - - - - - - - - - - - ->
  <table>
    <tr>
      <td colspan="2">Hardware Type</td>
      <td>Protocol Type</td>
    </tr>
    <tr>
      <td>Hardware Length</td>
      <td>Protocol Length</td>
      <td>Operation 1:Request 2:Reply</td>
    </tr>
    <tr><td colspan="3">Sender Hardware Address</td></tr>
    <tr><td colspan="3">Sender Protocol Address</td></tr>
    <tr><td colspan="3">Target Hardware Address</td></tr>
    <tr><td colspan="3">Target Protocol Address</td></tr>
  </table>
  Ethernet header (14bytes) + ARP header(28bytes) = 42bytes
  ; Ethernet header = DST MAC(6bytes) + SRC MAC(6bytes) + Type(2bytes)

  WireShark를 통해서 APR를 캡쳐했을 때, 42bytes가 잡히는 것을 확인할 수 있다.
