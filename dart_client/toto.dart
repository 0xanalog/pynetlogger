import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';

void main() async {
  final server = await HttpServer.bind(InternetAddress.anyIPv4, 8080);
  print('Server listening on port ${server.port}');

  runApp(MyApp(server));
}

class MyApp extends StatefulWidget {
  final HttpServer server;

  MyApp(this.server);

  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  List<dynamic> _logs = [];
  TextEditingController _searchController = TextEditingController();

  @override
  void initState() {
    super.initState();
    widget.server.listen((request) async {
      if (request.method == 'POST' && request.uri.path == '/logs') {
        var jsonString = await utf8.decodeStream(request);
        setState(() {
          _logs = jsonDecode(jsonString);
        });
        request.response.statusCode = HttpStatus.ok;
        request.response.close();
      } else {
        request.response.statusCode = HttpStatus.notFound;
        request.response.close();
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Log Viewer',
      home: Scaffold(
        appBar: AppBar(
          title: Text('Log Viewer'),
        ),
        body: Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: TextField(
                controller: _searchController,
                decoration: InputDecoration(
                  labelText: 'Search',
                  border: OutlineInputBorder(),
                ),
                onChanged: (text) {
                  setState(() {});
                },
              ),
            ),
            Expanded(
              child: ListView.builder(
                itemCount: _logs.length,
                itemBuilder: (BuildContext context, int index) {
                  var log = _logs[index];
                  if (_searchController.text.isNotEmpty &&
                      !jsonEncode(log).contains(_searchController.text)) {
                    return SizedBox.shrink();
                  } else {
                    return ListTile(
                      title: Text(
                        '${log['timestamp']} - ${log['message']}',
                      ),
                      subtitle: Text('${log['packet']}'),
                    );
                  }
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}
