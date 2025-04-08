import 'dart:convert';
import 'package:http/http.dart' as http;

Future<void> sendRequest() async {
  final uri = Uri.parse("http://localhost:18080/");
  
  final Map<String, dynamic> data = {
    "type": 3,
    "length": 20,
    "uuid": "1234567890123456",
    "transaction_id": "abcdef123456",
    "magic_cookie": 0x2112A442 // Valor numérico, sem aspas
  };

  final response = await http.post(
    uri,
    headers: {"Content-Type": "application/json"},
    body: jsonEncode(data),
  );

  print("Status Code: ${response.statusCode}");

  if (response.statusCode == 500) {
    final Map<String, dynamic> responseData = jsonDecode(response.body);
    
    String uuidString = responseData["uuid"];

    // Corrigindo a leitura para pegar apenas os 16 bytes reais
    List<int> uuidBytes = uuidString.codeUnits; 
    String uuidHex = uuidBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');

    print("UUID na resposta (hex): $uuidHex");
  } else {
    print("Erro: ${response.body}");
  }
}

void main() {
  sendRequest();
}