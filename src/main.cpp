#include <iostream>
#include "NatTypeDetector.h"
#include "Exception.h"

using namespace std;


int main(int argc, char* argv[])
{
  if (argc != 3)
  {
    cout << "Usage: " << argv[0] << " server1 server2" << endl;

    return 1;
  }

  try
  {
    NatTypeDetector natTypeDetector;
    natTypeDetector.execute(argv[1], argv[2]);
    //natTypeDetector.execute("stun.ekiga.net", "stun.sipnet.ru");
    natTypeDetector.print_result();
  }
  catch (const Exception& exception)
  {
    cerr << exception.what() << endl;
  }

  return 0;
}
