import org.omg.CORBA.PUBLIC_MEMBER;

import java.util.ArrayList;
import java.util.Vector;

/*
* add desigin pattern example
* */
public class DesignPattern {

    public static void testSingletonHungry() {

        SingletonHungry.getInstance().printf();
    }

    public static void testSingletonLazy() {

        SingletonLay.getInstance().printf();
    }

    public static void testStrategy() {

        ContextStrategy stategy1 = new ContextStrategy(new StudentStrategy());
        ContextStrategy stategy2 = new ContextStrategy(new TeacherStrategy());

        stategy1.printf();
        stategy2.printf();
    }

    public static void testAdapter() {

        ClassAdapter classAdapter = new ClassAdapter();

        ObjectAdapter objectAdapter = new ObjectAdapter(new StudentAdapter());

        classAdapter.run();
        classAdapter.fly();

        objectAdapter.run();
        objectAdapter.fly();
    }

    public static void testObserver() {

        StudentObserver s1 = new StudentObserver();
        StudentObserver s2 = new StudentObserver();

        TeacherSubject t = new TeacherSubject();

        t.registerObserver(s1);
        t.registerObserver(s2);

        t.setName("zhaokun");

        System.out.println(s1.getName());
        System.out.println(s2.getName());

        t.setName("kunzhao");

        System.out.println(s1.getName());
        System.out.println(s2.getName());

    }

    public static void testComposite() {

        FileComposite root = new FileComposite("root");
        DocComposite doc1 = new DocComposite("doc1");

        FileComposite file1 = new FileComposite("file");
        DocComposite doc2 = new DocComposite("doc2");
        file1.add(doc2);

        root.add(doc1);
        root.add(file1);

        root.display(1);

    }

    public static void testDecorator() {

        A4CarDecorator A4 = new A4CarDecorator();

        Decorator d1 = new GPSDecorator();

        d1.setCar(A4);

        WheelDecorator w1 = new WheelDecorator();

        w1.setCar(d1);

        System.out.println(w1.getCost());
    }

    public static void testCommand() {

        WaiterInvoker w = new WaiterInvoker();

        PlayCommander p = new PlayCommander();

        w.setCommander(p);

        w.execute();
    }

    public static void testState() {

        Room room = new Room();
        State s = new FreeState();

        room.setState(s);

        room.book();

        room.checkin();

        room.checkout();

    }

    public static void testBridge() {

        BridgeColor color = new RedColor();
        BridgePen pen = new BigBrigePen();

        pen.setColor(color);

        pen.printf();
    }

    public static void main(String args[]) {

//        testSingletonHungry();
//        testSingletonLazy();
//        testStrategy();
//        testAdapter();
//        testObserver();
//        testComposite();
//        testDecorator();
//        testCommand();
//        testState();
        testBridge();
    }
}


/*********************************单例模式****************************************/
//单例模式-恶汉模式
 class SingletonHungry {

    //指向自己实例的私有静态引用
    private static SingletonHungry singletonHungry = new SingletonHungry();

    //私有的构造方法
    private SingletonHungry() {}

    //已自己实例为返回值的静态公有方法
    public static SingletonHungry getInstance() {

        return singletonHungry;
    }

    public void printf() {
        System.out.println("SingletonHungry");
    }
}

//单例模式-懒汉模式
class SingletonLay {

    //指向自己实例的私有静态引用
    private static SingletonLay singletonLazy;

    //私有的构造方法
    private SingletonLay() {}

    //已自己实例为返回值的静态公有方法
    public static SingletonLay getInstance() {

        if(null == singletonLazy) {
            synchronized(SingletonLay.class) {
                if(null == singletonLazy ) {
                    singletonLazy = new SingletonLay();
                }
            }
        }
        return singletonLazy;
    }

    public void printf() {
        System.out.println("SingletonLay");
    }
}

/*********************************策略模式****************************************/
interface IStrategy { //定义抽象策略类
    void printf();
}

class StudentStrategy implements IStrategy { //定义具体策略实现类

    @Override
    public void printf() {
        System.out.println("StudentStrategy");
    }
}

class TeacherStrategy implements IStrategy { //定义具体策略实现类

    @Override
    public void printf() {
        System.out.println("TeacherStrategy");
    }
}

class ContextStrategy { //定义环境类

    private IStrategy strategy;

    public ContextStrategy(IStrategy strategy) {
        this.strategy = strategy;
    }

    public void printf() {
        strategy.printf();
    }
}

/*********************************适配器模式****************************************/
interface IAdapter { //被确定的目标接口

    void run();
    void fly();
}

class StudentAdapter { //被确定被适配者

    public void run() {
        System.out.println("StudentAdapter run");
    }
}

//类适配器
class ClassAdapter extends StudentAdapter implements IAdapter { //类适配器

    @Override
    public void fly() {
        System.out.println("ClassAdapter fly");
    }
}

class ObjectAdapter implements IAdapter { //对象适配器

    private StudentAdapter studentAdapter; //使用组合的方式,里面包含一个该类型的实例

    public ObjectAdapter(StudentAdapter s) {
        studentAdapter = s;
    }

    @Override
    public void run() {
        studentAdapter.run();
    }

    @Override
    public void fly() {
        System.out.println("ObjectAdapter fly");
    }
}

/*********************************观察者模式****************************************/
interface ISubject { //被观察者需要实现的接口
    void registerObserver(IObserver o);
    void removerObserver(IObserver o);
    void notifyOberver();
}

interface IObserver { //观察者需要实现的接口
    void update(Object o);
}

class TeacherSubject implements ISubject { //具体的被观察者对象

    private ArrayList<IObserver> observerList = new ArrayList<IObserver>(); //被观察者对象中含有一个容器,里面装载着观察者

    public String getName() {
        return name;
    }

    public void setName(String name) { //当被观察者发生变化是,即可通知观察者
        this.name = name;

        notifyOberver();
    }

    private String name;

    @Override
    public void registerObserver(IObserver o) {
        observerList.add(o);
    }

    @Override
    public void removerObserver(IObserver o) {
        observerList.remove(o);
    }

    @Override
    public void notifyOberver() {

        int length = observerList.size();
        for (int i = 0;i < length;i++) {
            observerList.get(i).update(name);
        }
    }
}

class StudentObserver implements IObserver {

    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public void update(Object o) {
         name = (String)o;
    }
}

/*********************************组合模式****************************************/
abstract class ComponentComposite {

    protected String name;

    public ComponentComposite(String name) {
        this.name = name;
    }

    public abstract void add(ComponentComposite c);
    public abstract void remove(ComponentComposite c);
    public abstract void display(int depth);
}

class DocComposite extends ComponentComposite {

    public DocComposite(String name) {
            super(name);
    }
    @Override
    public void add(ComponentComposite c) {
        System.out.println("我是文件不能进行添加操作");
    }

    @Override
    public void remove(ComponentComposite c) {
        System.out.println("我是文件不能进行删除操作");
    }

    @Override
    public void display(int depth) {
        System.out.println(depth + name);
    }
}

class FileComposite extends ComponentComposite {

    private ArrayList<ComponentComposite> list = new ArrayList<ComponentComposite>();

    public FileComposite(String name) {
        super(name);
    }

    @Override
    public void add(ComponentComposite c) {
        list.add(c);
    }

    @Override
    public void remove(ComponentComposite c) {
        list.remove(c);
    }

    @Override
    public void display(int depth) {
        System.out.println(depth + name);
        int length = list.size();
        for (int i = 0;i < length;i++) {
            list.get(i).display(1+depth);
        }
    }
}

/*********************************装饰模式****************************************/
abstract class CarDecorator { //被装饰者

    protected int cost;
    public abstract int getCost();
}

class A4CarDecorator extends CarDecorator {

    public A4CarDecorator() {
        cost = 4;
    }

    @Override
    public int getCost() {
        return cost;
    }
}

class Decorator extends CarDecorator { //装饰者

    protected CarDecorator car;

    @Override
    public int getCost() {
        return cost + car.getCost();
    }

    public void setCar(CarDecorator car) {
        this.car = car;
    }
}

class GPSDecorator extends Decorator {

    public GPSDecorator() {
        cost = 1;
    }
}

class WheelDecorator extends Decorator {

    public WheelDecorator() {
        cost = 1;
    }
}

/*********************************命令者模式****************************************/
class WaiterInvoker { //命令传递者

    private Commander commander;

    public void setCommander(Commander commander) {
        this.commander = commander;
    }

    public void execute() {
        commander.execute();
    }
}

interface Commander { //命令接口

    void execute();
}

class PlayCommander implements Commander { //对外提供的具体命令

    @Override
    public void execute() {
        new StudentExecuter().execute();
    }
}

class SleepCommander implements Commander {

    @Override
    public void execute() {
        new TeacherExecuter().execute();
    }
}

interface RealExecuter { //真正执行命令的接口

    void execute();
}

class StudentExecuter implements RealExecuter {

    @Override
    public void execute() {

        System.out.println("StudentExecuter");
    }
}

class TeacherExecuter implements RealExecuter {

    @Override
    public void execute() {

        System.out.println("TeacherExecuter");
    }
}

/*********************************状态模式****************************************/
interface State { //定义状态接口
    void book();
    void unbook();
    void checkin();
    void checkout();
}

class FreeState implements State {

    public FreeState() {
        System.out.println("空闲状态");
    }

    @Override
    public void book() {
        System.out.println("当前为空闲状态正在进行预定操作");
    }

    @Override
    public void unbook() {
        System.out.println("当前为空闲状态不能进行取消预定操作");
    }

    @Override
    public void checkin() {
        System.out.println("当前为空闲状态正在进行入住操作");
    }

    @Override
    public void checkout() {
        System.out.println("当前为空闲状态正在进行取消入住操作");
    }

}

class BookState implements State {

    public BookState() {
        System.out.println("预定状态");
    }

    @Override
    public void book() {
        System.out.println("当前为预定状态不能进行预定操作");
    }

    @Override
    public void unbook() {
        System.out.println("当前为预定状态正在进行取消预定操作");
    }

    @Override
    public void checkin() {
        System.out.println("当前为预定状态正在进行入住操作");
    }

    @Override
    public void checkout() {
        System.out.println("当前为预定状态不能进行取消入住操作");
    }

}

class InState implements State {

    public InState() {
        System.out.println("入住状态");
    }

    @Override
    public void book() {
        System.out.println("当前为入住状态不能进行预定操作");
    }

    @Override
    public void unbook() {
        System.out.println("当前为入住状态不能进行取消预定操作");
    }

    @Override
    public void checkin() {
        System.out.println("当前为入住状态不能进行入住操作");
    }

    @Override
    public void checkout() {
        System.out.println("当前为入住状态正在进行取消入住操作");
    }

}

class Room {

    private State state;

    public void setState(State state) {
        this.state = state;
    }

    public void book() {
       state.book();
       state = new BookState();
    }

    public void unbook() {
        state.unbook();
        state = new FreeState();
    }

    public void checkin() {
        state.checkin();
        state = new InState();
    }

    public void checkout() {
        state.checkout();
        state = new FreeState();
    }
}

/*********************************桥接模式****************************************/

interface BridgeColor {

    void printfColor();
}

class RedColor implements BridgeColor {

    @Override
    public void printfColor() {
        System.out.println("我是红颜色");
    }
}

class BlackColor implements BridgeColor {

    @Override
    public void printfColor() {
        System.out.println("我是黑颜色");
    }
}

abstract class BridgePen {

    protected  BridgeColor color;

    public BridgePen(BridgeColor color) {
        this.color = color;
    }

    public BridgePen() {}

    public void setColor(BridgeColor color) {
        this.color = color;
    }

    public abstract  void printf();
}

class BigBrigePen extends BridgePen {

    @Override
    public void printf() {
        System.out.print("我是大号钢笔,颜色是:");
        color.printfColor();
    }
}

class LiteBrigePen extends BridgePen {

    @Override
    public void printf() {
        System.out.print("我是小号钢笔,颜色是:");
        color.printfColor();
    }
}

/*********************************迭代器模式****************************************/
class Menu {
    private String id;
    private String name;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}

interface Iterator {

    Menu first();
    Menu next();
    boolean isDone();
}

class ImplIterator implements Iterator {

    ArrayList<Menu> list;
    int current = 0;

    public ImplIterator(ArrayList<Menu> l) {
        list = l;
    }

    @Override
    public Menu first() {
        current = 0;
        return list.get(current);
    }

    @Override
    public Menu next() {
        current++;
        return list.get(current);
    }

    @Override
    public boolean isDone() {
        return current > (list.size()-1);
    }
}

interface TV {
    Iterator getIterator();
}

class HaierTV implements TV {

    ArrayList<Menu> list;

    public HaierTV() {
        list = new ArrayList<Menu>();

        Menu men1 = new Menu();
        men1.setId("1");
        men1.setName("zhao1");

        list.add(men1);

        Menu men2 = new Menu();
        men1.setId("2");
        men1.setName("zhao2");

        list.add(men2);

    }

    @Override
    public Iterator getIterator() {
        return new ImplIterator(list);
    }
}