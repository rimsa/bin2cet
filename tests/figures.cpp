#include <iostream>
#include <string>

class Figure {
  public:
    Figure(double a, double b) : a{a}, b{b} {}
    virtual ~Figure() {}
    virtual double area() = 0;
  protected:
    double a, b;
};

class Triangle : public Figure {
  public:
    Triangle(double a, double b) : Figure(a, b) {}
    virtual ~Triangle() {}
    double area() { return (a * b) / 2; }
};

class Rectangle : public Figure {
  public:
    Rectangle(double a, double b) : Figure(a, b) {}
    virtual ~Rectangle() {}
    double area() { return a * b; }
};

int main(int argc, char* argv[]) {
  if (argc != 4) {
    std::cout << "Usage: " << argv[0] << " [Dimension 1] [Dimension 2] [triangle|rectangle]" << std::endl;
    return 0;
  }

  double x = atof(argv[1]);
  double y = atof(argv[2]);
  std::string type(argv[3]);
 
  Figure* f = nullptr;
  if (type == "triangle")
    f = new Triangle(x, y);
  else if (type == "rectangle")
    f = new Rectangle(x, y);
  else {
    std::cerr << "Invalid figure type: " << argv[3] << std::endl;
    return 1;
  }

  std::cout << "The area of a (" << x << "," << y << ") " << argv[3] << " is " << f->area() << std::endl;
  delete f;

  return 0;
}

