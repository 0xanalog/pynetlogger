import 'dart:convert';
import 'dart:html';
import 'package:flutter/material.dart';

void main() async {
  runApp(MyApp());
}

class MyApp extends StatefulWidget {
  final HttpRequest? data;
  MyApp({this.data});

  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  List<dynamic> _logs = [];
  TextEditingController _searchController = TextEditingController();

  @override
  void initState() {
    super.initState();
    if (widget.data != null) {
      setState(() {
        _logs = jsonDecode(widget.data?.responseText ?? "");
        print(_logs);
      });
    }
    // widget.server.listen((request) async {
    //   if (request.method == 'POST' && request.uri.path == '/logs') {
    //     var jsonString = await utf8.decodeStream(request);
    //     setState(() {
    //       _logs = jsonDecode(jsonString);
    //     });
    //     request.response.statusCode = HttpStatus.ok;
    //     request.response.close();
    //   } else {
    //     request.response.statusCode = HttpStatus.notFound;
    //     request.response.close();
    //   }
    // });
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
